import fs from "node:fs";
import errs from "../lib/error.js";
import { compile, PATHS } from "../lib/sentinel/compile.js";
import { fetchFeed } from "../lib/sentinel/feeds.js";
import * as geoip from "../lib/sentinel/geoip.js";
import { cleanup as cleanupLists, writeFile as writeListFile } from "../lib/sentinel/ipset.js";
import { ensureSecrets } from "../lib/sentinel/secrets.js";
import * as validate from "../lib/sentinel/validate.js";
import { sentinel as logger } from "../logger.js";
import proxyHostModel from "../models/proxy_host.js";
import redirectionHostModel from "../models/redirection_host.js";
import hostModel from "../models/sentinel_host.js";
import listModel from "../models/sentinel_list.js";
import ruleModel from "../models/sentinel_rule.js";
import internalAuditLog from "./audit-log.js";
import internalNginx from "./nginx.js";
import internalUnderAttack from "./sentinel-underattack.js";

// Bumped when the per-host Sentinel template changes, so existing host configs are
// written again once at startup.
const HOST_TEMPLATE_VERSION = 2;
const HOST_TEMPLATE_MARKER = `${PATHS.dir}/.host-template-version`;
const FEED_TICK_MS = 60 * 1000;
const FEED_RETRY_MS = 15 * 60 * 1000;

// Last deployment result, reported by the status endpoint
const lastDeploy = { ok: true, error: "", at: null, rules: 0 };

// Deployments run one at a time
let deployChain = Promise.resolve();
const serialize = (fn) => {
	const run = deployChain.then(fn, fn);
	deployChain = run.catch(() => {});
	return run;
};

const toValidationError = (err) => {
	if (err instanceof validate.ValidationErrors) {
		return new errs.ValidationError(err.message);
	}
	return err;
};

const feedRunning = new Set();
let feedTimer = null;
let geoRunning = false;

const internalSentinel = {
	// ------------------------------------------------------------------ deploy

	/**
	 * Writes rules.json from the database, tests nginx and reloads it. When nginx refuses
	 * the new configuration, the previous rules.json is put back and the error is thrown.
	 *
	 * @returns {Promise<Object>}  {ok, error, at, rules}
	 */
	deploy: () =>
		serialize(async () => {
			let previous = null;
			try {
				previous = fs.readFileSync(PATHS.rules);
			} catch {
				// first deployment
			}
			const { config, lists, listHashes, usesCountry } = await internalSentinel.writeRules();

			try {
				await internalNginx.test();
			} catch (err) {
				if (previous !== null) {
					fs.writeFileSync(PATHS.rules, previous);
				} else {
					fs.unlinkSync(PATHS.rules);
				}
				const msg = String(err.message || err)
					.split("\n")
					.filter((l) => l && !l.includes("/var/log/nginx/error.log"))
					.join("\n");
				Object.assign(lastDeploy, { ok: false, error: msg, at: new Date().toISOString() });
				logger.error(`nginx refused the Sentinel configuration: ${msg}`);
				throw new errs.ConfigurationError(`nginx refused the Sentinel configuration: ${msg}`);
			}
			try {
				await internalNginx.reload();
			} catch (err) {
				// nginx may not be running yet at startup: it reads the file when it starts
				logger.warn(`nginx reload failed: ${err.message}`);
			}
			Object.assign(lastDeploy, {
				ok: true,
				error: "",
				at: new Date().toISOString(),
				rules: config.rules.length,
			});

			// keep range files still referenced, and the stored files of IP feeds
			for (const l of lists) {
				if (l.data_hash) listHashes.add(l.data_hash);
			}
			cleanupLists(PATHS.lists, listHashes);

			if (usesCountry) {
				internalSentinel.ensureGeoip();
			}
			return { ...lastDeploy };
		}),

	/**
	 * Compiles rules.json from the database and writes it, without testing or reloading
	 * nginx (deploy() does both; nginx.configure() writes it before testing a host).
	 *
	 * @returns {Promise<Object>}
	 */
	writeRules: async () => {
		fs.mkdirSync(PATHS.dir, { recursive: true });
		ensureSecrets(PATHS.secrets);
		const [rules, lists, proxyHosts, redirectionHosts, hostSettings] = await Promise.all([
			ruleModel
				.query()
				.where("is_deleted", 0)
				.orderBy([{ column: "position" }, { column: "id" }]),
			listModel.query().where("is_deleted", 0),
			proxyHostModel.query().where("is_deleted", 0).select("id", "enabled", "block_exploits"),
			redirectionHostModel.query().where("is_deleted", 0).select("id", "enabled", "block_exploits"),
			hostModel.query(),
		]);
		const { config, listHashes, usesCountry } = compile({
			rules,
			lists,
			proxyHosts,
			redirectionHosts,
			hostSettings,
		});
		const tmp = `${PATHS.rules}.tmp`;
		fs.writeFileSync(tmp, JSON.stringify(config));
		fs.renameSync(tmp, PATHS.rules);
		return { config, lists, listHashes, usesCountry };
	},

	/**
	 * Called by nginx.configure() before it tests a proxy or redirection host's new
	 * config, so a new host, or a changed "Block Common Exploits", is in rules.json when
	 * nginx reloads. Never fails the host's save.
	 */
	syncHosts: () =>
		serialize(() => internalSentinel.writeRules()).catch((err) => {
			logger.error(`Could not update Sentinel hosts: ${err.message}`);
		}),

	/**
	 * Runs a database change and deploys it. When the deployment fails, undo() puts the
	 * database back and the previous configuration stays.
	 */
	apply: async (change, undo) => {
		const result = await change();
		try {
			await internalSentinel.deploy();
		} catch (err) {
			if (undo) {
				await undo(result);
				await internalSentinel.deploy().catch(() => {});
			}
			throw err;
		}
		return result;
	},

	// ------------------------------------------------------------------ startup

	init: async () => {
		for (const d of [PATHS.dir, PATHS.lists]) {
			fs.mkdirSync(d, { recursive: true });
		}
		try {
			await internalSentinel.regenerateHostsOnce();
		} catch (err) {
			logger.error(`Could not update host configurations: ${err.message}`);
		}
		try {
			await internalSentinel.deploy();
		} catch (err) {
			logger.error(`Initial deployment failed: ${err.message}`);
		}
		internalUnderAttack.start();
		if (!feedTimer) {
			setTimeout(() => internalSentinel.refreshDueFeeds(), 20 * 1000);
			feedTimer = setInterval(() => internalSentinel.refreshDueFeeds(), FEED_TICK_MS);
		}
	},

	/**
	 * Hosts created before Sentinel have no hook in their nginx config: write them again
	 * once. A host whose new config nginx refuses keeps its old file.
	 */
	regenerateHostsOnce: async () => {
		let have = 0;
		try {
			have = Number.parseInt(fs.readFileSync(HOST_TEMPLATE_MARKER, "utf8"), 10) || 0;
		} catch {
			// not done yet
		}
		if (have >= HOST_TEMPLATE_VERSION) {
			return;
		}
		logger.info("Updating proxy and redirection host configurations for Sentinel ...");
		for (const [model, type] of [
			[proxyHostModel, "proxy_host"],
			[redirectionHostModel, "redirection_host"],
		]) {
			const rows = await model
				.query()
				.where("is_deleted", 0)
				.andWhere("enabled", 1)
				.allowGraph(model.defaultAllowGraph)
				.withGraphFetched(`[${model.defaultExpand.join(", ")}]`);
			for (const row of rows) {
				const file = internalNginx.getConfigName(type, row.id);
				let old = null;
				try {
					old = fs.readFileSync(file);
				} catch {
					// offline host without a config: leave it alone
					continue;
				}
				try {
					await internalNginx.generateConfig(type, row);
					await internalNginx.test();
				} catch (err) {
					logger.warn(`${type} #${row.id}: keeping the previous config (${err.message.split("\n")[0]})`);
					fs.writeFileSync(file, old);
				}
			}
		}
		fs.writeFileSync(HOST_TEMPLATE_MARKER, String(HOST_TEMPLATE_VERSION));
	},

	// ------------------------------------------------------------------ rules

	getRules: async (access) => {
		await access.can("sentinel:list");
		return ruleModel
			.query()
			.where("is_deleted", 0)
			.orderBy([{ column: "position" }, { column: "id" }]);
	},

	getRule: async (access, id) => {
		await access.can("sentinel:get");
		const row = await ruleModel.query().where("is_deleted", 0).andWhere("id", id).first();
		if (!row) {
			throw new errs.ItemNotFoundError(id);
		}
		return row;
	},

	validateRule: async (data) => {
		const [lists, hosts] = await Promise.all([
			listModel.query().where("is_deleted", 0).select("id", "kind"),
			proxyHostModel.query().where("is_deleted", 0).select("id"),
		]);
		const kinds = new Map(lists.map((l) => [Number(l.id), l.kind]));
		const hostIds = new Set(hosts.map((h) => Number(h.id)));
		try {
			return validate.securityRule(
				data,
				(id) => kinds.get(id) || "",
				(id) => hostIds.has(id),
			);
		} catch (err) {
			throw toValidationError(err);
		}
	},

	createRule: async (access, data) => {
		await access.can("sentinel:update");
		const count = await ruleModel.query().where("is_deleted", 0).resultSize();
		if (count >= validate.LIMITS.maxRules) {
			throw new errs.ValidationError(`at most ${validate.LIMITS.maxRules} rules`);
		}
		const clean = await internalSentinel.validateRule(data);
		const last = await ruleModel.query().where("is_deleted", 0).max("position as max").first();
		const row = await internalSentinel.apply(
			() =>
				ruleModel.query().insertAndFetch({
					...clean,
					owner_user_id: access.token.getUserId(1),
					position: (Number(last?.max) || 0) + 1,
					meta: {},
				}),
			(created) => ruleModel.query().deleteById(created.id),
		);
		await internalAuditLog.add(access, {
			action: "created",
			object_type: "sentinel-rule",
			object_id: row.id,
			meta: clean,
		});
		return row;
	},

	updateRule: async (access, id, data) => {
		await access.can("sentinel:update");
		const before = await internalSentinel.getRule(access, id);
		const merged = {
			name: before.name,
			description: before.description,
			enabled: before.enabled,
			action: before.action,
			status_code: before.status_code,
			challenge: before.challenge,
			scope: before.scope,
			host_ids: before.host_ids,
			expression: before.expression,
			...data,
		};
		const clean = await internalSentinel.validateRule(merged);
		const fields = Object.keys(clean);
		const restore = Object.fromEntries(fields.map((k) => [k, before[k]]));
		await internalSentinel.apply(
			() => ruleModel.query().patchAndFetchById(id, clean),
			() => ruleModel.query().patchAndFetchById(id, restore),
		);
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "sentinel-rule",
			object_id: id,
			meta: clean,
		});
		return internalSentinel.getRule(access, id);
	},

	deleteRule: async (access, id) => {
		await access.can("sentinel:update");
		const before = await internalSentinel.getRule(access, id);
		await internalSentinel.apply(
			() => ruleModel.query().patchAndFetchById(id, { is_deleted: true }),
			() => ruleModel.query().patchAndFetchById(id, { is_deleted: false }),
		);
		await internalAuditLog.add(access, {
			action: "deleted",
			object_type: "sentinel-rule",
			object_id: id,
			meta: { name: before.name },
		});
		return true;
	},

	/**
	 * @param {Access}   access
	 * @param {number[]} ids  every rule id, in the new evaluation order
	 */
	orderRules: async (access, ids) => {
		await access.can("sentinel:update");
		const rows = await ruleModel.query().where("is_deleted", 0).select("id", "position");
		const have = new Set(rows.map((r) => Number(r.id)));
		const want = [...new Set(ids.map(Number))];
		if (want.length !== have.size || want.some((id) => !have.has(id))) {
			throw new errs.ValidationError("the order must list every rule exactly once");
		}
		const before = new Map(rows.map((r) => [Number(r.id), r.position]));
		await internalSentinel.apply(
			async () => {
				for (let i = 0; i < want.length; i++) {
					await ruleModel
						.query()
						.patch({ position: i + 1 })
						.where("id", want[i]);
				}
			},
			async () => {
				for (const [id, position] of before) {
					await ruleModel.query().patch({ position }).where("id", id);
				}
			},
		);
		return internalSentinel.getRules(access);
	},

	// ------------------------------------------------------------------ lists

	/**
	 * Lists without their entries (IP lists can be large); getList returns them.
	 */
	getLists: async (access) => {
		await access.can("sentinel:list");
		const rows = await listModel.query().where("is_deleted", 0).orderBy("name");
		return rows.map(internalSentinel.listSummary);
	},

	listSummary: (row) => {
		const { items, ...rest } = row;
		return { ...rest, item_count: row.source_url && row.kind === "ip" ? row.item_count : (items || []).length };
	},

	getList: async (access, id) => {
		await access.can("sentinel:get");
		const row = await listModel.query().where("is_deleted", 0).andWhere("id", id).first();
		if (!row) {
			throw new errs.ItemNotFoundError(id);
		}
		return { ...row, item_count: internalSentinel.listSummary(row).item_count };
	},

	createList: async (access, data) => {
		await access.can("sentinel:update");
		let clean;
		try {
			clean = validate.list(data);
		} catch (err) {
			throw toValidationError(err);
		}
		const row = await listModel.query().insertAndFetch({
			...clean,
			owner_user_id: access.token.getUserId(1),
			item_count: clean.items.length,
			meta: {},
		});
		await internalAuditLog.add(access, {
			action: "created",
			object_type: "sentinel-list",
			object_id: row.id,
			meta: { name: clean.name, kind: clean.kind, source_url: clean.source_url },
		});
		// a new list is used by no rule yet: nothing to deploy
		if (row.source_url) {
			internalSentinel.refreshFeed(row.id).catch(() => {});
		}
		return internalSentinel.getList(access, row.id);
	},

	updateList: async (access, id, data) => {
		await access.can("sentinel:update");
		const before = await internalSentinel.getList(access, id);
		let clean;
		try {
			clean = validate.list({
				name: before.name,
				description: before.description,
				kind: before.kind,
				source_url: before.source_url,
				refresh_s: before.refresh_s,
				items: before.source_url ? [] : before.items,
				...data,
			});
		} catch (err) {
			throw toValidationError(err);
		}
		if (clean.kind !== before.kind && (await internalSentinel.listUsedBy(id)).length) {
			throw new errs.ValidationError("the kind of a list used by rules cannot change");
		}
		const patch = { ...clean };
		const urlChanged = clean.source_url !== before.source_url || clean.kind !== before.kind;
		if (clean.source_url) {
			// a feed keeps its downloaded entries until the next refresh
			delete patch.items;
			if (urlChanged) Object.assign(patch, { fetched_on: null, fetch_error: "" });
		} else {
			Object.assign(patch, { data_hash: "", item_count: clean.items.length, fetched_on: null, fetch_error: "" });
		}
		const restore = Object.fromEntries(Object.keys(patch).map((k) => [k, before[k]]));
		await internalSentinel.apply(
			() => listModel.query().patchAndFetchById(id, patch),
			() => listModel.query().patchAndFetchById(id, restore),
		);
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "sentinel-list",
			object_id: id,
			meta: { name: clean.name, kind: clean.kind, source_url: clean.source_url },
		});
		if (clean.source_url && urlChanged) {
			internalSentinel.refreshFeed(id).catch(() => {});
		}
		return internalSentinel.getList(access, id);
	},

	/**
	 * @param   {number} id
	 * @returns {Promise<Object[]>}  rules that reference the list
	 */
	listUsedBy: async (id) => {
		const rules = await ruleModel.query().where("is_deleted", 0);
		const ref = `list:${id}`;
		return rules.filter((r) =>
			(r.expression?.groups || []).some((g) => g.some((c) => (c.value || []).includes(ref))),
		);
	},

	deleteList: async (access, id) => {
		await access.can("sentinel:update");
		const before = await internalSentinel.getList(access, id);
		const used = await internalSentinel.listUsedBy(id);
		if (used.length) {
			throw new errs.ValidationError(`the list is used by rule "${used[0].name}": remove it from the rule first`);
		}
		await listModel.query().patchAndFetchById(id, { is_deleted: true });
		await internalAuditLog.add(access, {
			action: "deleted",
			object_type: "sentinel-list",
			object_id: id,
			meta: { name: before.name },
		});
		return true;
	},

	refreshList: async (access, id) => {
		await access.can("sentinel:update");
		const row = await internalSentinel.getList(access, id);
		if (!row.source_url) {
			throw new errs.ValidationError("only lists with a URL can be refreshed");
		}
		await internalSentinel.refreshFeed(id);
		return internalSentinel.getList(access, id);
	},

	// ------------------------------------------------------------------ feeds

	/**
	 * Downloads a feed. A failed download keeps the last good entries; the gateway is
	 * redeployed only when the entries changed and a rule uses the list.
	 *
	 * @param {number} id
	 */
	refreshFeed: async (id) => {
		if (feedRunning.has(id)) {
			return;
		}
		feedRunning.add(id);
		try {
			const row = await listModel.query().where("is_deleted", 0).andWhere("id", id).first();
			if (!row?.source_url) {
				return;
			}
			const now = new Date();
			let feed;
			try {
				feed = await fetchFeed(row.source_url, row.kind);
			} catch (err) {
				logger.warn(`List "${row.name}": refresh failed: ${err.message}`);
				await listModel
					.query()
					.patch({ fetched_on: now, fetch_error: String(err.message).slice(0, 500) })
					.where("id", id);
				throw new errs.ValidationError(`refresh failed: ${err.message}`);
			}
			const patch = { fetched_on: now, fetch_error: (feed.warning || "").slice(0, 500), item_count: feed.count };
			let changed;
			if (row.kind === "ip") {
				const info = writeListFile(PATHS.lists, feed.set);
				changed = info.hash !== row.data_hash;
				patch.data_hash = info.hash;
			} else {
				changed = JSON.stringify(feed.items) !== JSON.stringify(row.items || []);
				patch.items = feed.items;
			}
			if (changed) {
				patch.changed_on = now;
			}
			await listModel.query().patch(patch).where("id", id);
			logger.info(`List "${row.name}": ${feed.count} entries${changed ? " (changed)" : ""}`);
			if (changed && (await internalSentinel.listUsedBy(id)).length) {
				await internalSentinel.deploy();
			}
		} finally {
			feedRunning.delete(id);
		}
	},

	refreshDueFeeds: async () => {
		let rows = [];
		try {
			rows = await listModel.query().where("is_deleted", 0).andWhereNot("source_url", "");
		} catch (err) {
			logger.error(`Could not read lists: ${err.message}`);
			return;
		}
		const now = Date.now();
		for (const row of rows) {
			const last = row.fetched_on ? new Date(row.fetched_on).getTime() : 0;
			const every = Math.max(row.refresh_s, 300) * 1000;
			const wait = row.fetch_error && !row.changed_on ? Math.min(every, FEED_RETRY_MS) : every;
			const missing = row.kind === "ip" && !row.data_hash;
			if (!last || now - last >= wait || (missing && now - last >= FEED_RETRY_MS)) {
				await internalSentinel.refreshFeed(row.id).catch(() => {});
			}
		}
	},

	// ------------------------------------------------------------------ country database

	/**
	 * Downloads the country database when a rule needs it and it is missing or old.
	 */
	ensureGeoip: () => {
		if (geoRunning) {
			return;
		}
		const st = geoip.status(PATHS.geo);
		const age = st.updated_on ? Date.now() - new Date(st.updated_on).getTime() : Number.POSITIVE_INFINITY;
		const lastTry = internalSentinel.geoLastTry || 0;
		if ((st.available && age < geoip.REFRESH_AGE_MS) || Date.now() - lastTry < 6 * 3600 * 1000) {
			return;
		}
		geoRunning = true;
		internalSentinel.geoLastTry = Date.now();
		logger.info("Downloading the IP to country database ...");
		geoip
			.refresh(PATHS.geo)
			.then((r) => {
				logger.info(`Country database installed (${r.ranges} ranges)`);
				internalSentinel.geoError = "";
				return internalSentinel.deploy();
			})
			.catch((err) => {
				internalSentinel.geoError = err.message;
				logger.error(`Country database download failed: ${err.message}`);
			})
			.finally(() => {
				geoRunning = false;
			});
	},

	geoLastTry: 0,
	geoError: "",

	// ------------------------------------------------------------------ under attack

	getUnderAttack: (access) => internalUnderAttack.list(access),
	setUnderAttack: (access, hostId, data) =>
		internalUnderAttack.update(access, hostId, data, (change, undo) => internalSentinel.apply(change, undo)),
	deactivateUnderAttack: (access, hostId) => internalUnderAttack.deactivate(access, hostId),
	underAttackEvents: async (access) => {
		await access.can("sentinel:list");
		return internalUnderAttack.events();
	},
	getAlerts: (access) => internalUnderAttack.getAlerts(access),
	setAlerts: (access, data) => internalUnderAttack.setAlerts(access, data),
	testAlert: (access) => internalUnderAttack.testAlert(access),

	// ------------------------------------------------------------------ status

	status: async (access) => {
		await access.can("sentinel:list");
		return {
			deploy: { ...lastDeploy },
			geoip: { ...geoip.status(PATHS.geo), downloading: geoRunning, error: internalSentinel.geoError },
			under_attack: {
				active: (await internalUnderAttack.list(access)).filter((h) => h.active).length,
				sync: internalUnderAttack.syncStatus(),
			},
		};
	},
};

export default internalSentinel;
