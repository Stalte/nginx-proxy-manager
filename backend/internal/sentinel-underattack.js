import fs from "node:fs";
import errs from "../lib/error.js";
import * as alerts from "../lib/sentinel/alerts.js";
import { PATHS } from "../lib/sentinel/compile.js";
import { ensureSecrets } from "../lib/sentinel/secrets.js";
import { statusRequest } from "../lib/sentinel/status.js";
import * as ua from "../lib/sentinel/underattack.js";
import * as validate from "../lib/sentinel/validate.js";
import { sentinel as logger } from "../logger.js";
import proxyHostModel from "../models/proxy_host.js";
import hostModel from "../models/sentinel_host.js";
import rateLimitModel from "../models/sentinel_rate_limit.js";
import internalAuditLog from "./audit-log.js";

const TICK_MS = 10 * 1000;
const MAX_PUSH_AGE_MS = 60 * 1000;
const MAX_EVENTS = 50;
const ALERTS_FILE = `${PATHS.dir}/alerts.json`;

let state = null;
let events = [];
let timer = null;
let running = false;
let lastPush = { at: 0, hash: "", ok: true, error: "" };
let lastAlert = { at: null, ok: true, error: "" };

const toValidationError = (err) =>
	err instanceof validate.ValidationErrors ? new errs.ValidationError(err.message) : err;

const loadState = () => {
	if (!state) {
		let raw = "";
		try {
			raw = fs.readFileSync(PATHS.underAttack, "utf8");
		} catch {
			// first start
		}
		state = ua.parseState(raw);
		try {
			const v = JSON.parse(raw);
			events = Array.isArray(v?.events) ? v.events.slice(-MAX_EVENTS) : [];
		} catch {
			events = [];
		}
	}
	return state;
};

const saveState = () => {
	const tmp = `${PATHS.underAttack}.tmp`;
	fs.writeFileSync(tmp, JSON.stringify({ ...state, events }));
	fs.renameSync(tmp, PATHS.underAttack);
};

const readAlerts = () => {
	try {
		return validate.alerts(JSON.parse(fs.readFileSync(ALERTS_FILE, "utf8")));
	} catch {
		return validate.alerts({});
	}
};

const notify = async (t) => {
	const cfg = readAlerts();
	if (!cfg.enabled || !cfg.url) {
		return;
	}
	const msg = {
		...alerts.underAttackText(t),
		event: t.on ? "under_attack.activated" : "under_attack.deactivated",
		data: { host_id: t.id, host: t.host, reason: t.reason, since: t.since, until: t.until, manual: !!t.manual },
	};
	try {
		await alerts.send(cfg, msg);
		lastAlert = { at: new Date().toISOString(), ok: true, error: "" };
	} catch (err) {
		lastAlert = { at: new Date().toISOString(), ok: false, error: String(err.message || err).slice(0, 300) };
		logger.warn(`Sentinel alert not sent: ${lastAlert.error}`);
	}
};

const record = (transitions) => {
	for (const t of transitions) {
		events.push({ ...t, at: new Date(t.at).toISOString() });
		if (t.on) {
			logger.warn(`Under attack mode activated for ${t.host}: ${t.reason}`);
		} else {
			logger.info(`Under attack mode deactivated for ${t.host}${t.manual ? " by an administrator" : ""}`);
		}
		notify(t);
	}
	events = events.slice(-MAX_EVENTS);
};

const firstDomain = (h) => (Array.isArray(h.domain_names) && h.domain_names[0]) || `#${h.id}`;

const internalUnderAttack = {
	/**
	 * Enabled proxy hosts in auto mode, with normalised settings.
	 */
	autoHosts: async () => {
		const rows = await hostModel.query().where("under_attack", "auto");
		if (!rows.length) {
			return [];
		}
		const hosts = await proxyHostModel
			.query()
			.where("is_deleted", 0)
			.andWhere("enabled", 1)
			.whereIn(
				"id",
				rows.map((r) => r.proxy_host_id),
			)
			.select("id", "domain_names");
		const byId = new Map(hosts.map((h) => [Number(h.id), h]));
		const out = [];
		for (const r of rows) {
			const h = byId.get(Number(r.proxy_host_id));
			if (!h) continue;
			try {
				out.push({ id: h.id, host: firstDomain(h), config: validate.underAttack(r).config });
			} catch {
				// invalid stored settings: compile.js leaves the host out as well
			}
		}
		return out;
	},

	/**
	 * One round: read the traffic, evaluate the auto hosts, push the active ones.
	 */
	tick: async (force = false) => {
		if (running) return;
		running = true;
		try {
			loadState();
			const hosts = await internalUnderAttack.autoHosts();
			const traffic = {};
			for (const w of new Set(hosts.map((h) => h.config.window_s))) {
				try {
					const res = await statusRequest(`/traffic?window=${w}`);
					traffic[w] = await res.json();
				} catch (err) {
					logger.debug?.(`Sentinel traffic not readable: ${err.message}`);
					traffic[w] = {};
				}
			}
			const now = Date.now();
			const { changed, transitions } = ua.evaluate(state, hosts, (id, w) => traffic[w]?.[String(id)], now);
			if (changed || transitions.length) {
				record(transitions);
				saveState();
			}
			await internalUnderAttack.push(force || changed);
		} catch (err) {
			logger.error(`Under attack evaluation failed: ${err.message}`);
		} finally {
			running = false;
		}
	},

	/**
	 * Sends the active hosts to the gateway when they changed, and at least every minute
	 * (a restarted nginx starts with empty shared memory).
	 */
	push: async (force) => {
		const now = Date.now();
		const body = JSON.stringify(ua.payload(loadState(), now));
		if (!force && body === lastPush.hash && lastPush.ok && now - lastPush.at < MAX_PUSH_AGE_MS) {
			return;
		}
		try {
			await statusRequest("/under-attack", {
				method: "PUT",
				headers: { "Content-Type": "application/json" },
				body,
			});
			lastPush = { at: now, hash: body, ok: true, error: "" };
		} catch (err) {
			lastPush = { at: now, hash: "", ok: false, error: err.message };
		}
	},

	start: () => {
		if (timer) return;
		ensureSecrets(PATHS.secrets);
		loadState();
		setTimeout(() => internalUnderAttack.tick(true), 5000);
		timer = setInterval(() => internalUnderAttack.tick(), TICK_MS);
	},

	// ------------------------------------------------------------------ API

	/**
	 * Every proxy host with its under-attack settings and live state.
	 */
	list: async (access) => {
		await access.can("sentinel:list");
		const [hosts, rows, limits] = await Promise.all([
			proxyHostModel.query().where("is_deleted", 0).select("id", "domain_names", "enabled").orderBy("id"),
			hostModel.query(),
			rateLimitModel.query().where("is_deleted", 0).andWhere("enabled", 1).select("id", "name", "host_ids"),
		]);
		const limitOf = new Map();
		for (const l of limits) {
			for (const h of l.host_ids || []) {
				if (!limitOf.has(Number(h))) limitOf.set(Number(h), { id: l.id, name: l.name });
			}
		}
		const byHost = new Map(rows.map((r) => [Number(r.proxy_host_id), r]));
		const st = loadState();
		const now = Date.now();
		return hosts.map((h) => {
			const row = byHost.get(Number(h.id));
			let s = { under_attack: "off", config: validate.underAttack({}).config };
			if (row) {
				try {
					s = validate.underAttack(row);
				} catch {
					s = { under_attack: "off", config: s.config };
				}
			}
			const a = st.active[String(h.id)];
			const auto = s.under_attack === "auto" && a && now < a.until;
			return {
				proxy_host_id: h.id,
				domain_names: h.domain_names,
				enabled: !!h.enabled,
				under_attack: s.under_attack,
				config: s.config,
				active: !!h.enabled && (s.under_attack === "on" || !!auto),
				since: auto ? new Date(a.since).toISOString() : null,
				until: auto ? new Date(a.until).toISOString() : null,
				reason: auto ? a.reason : "",
				no_autoban: !!row?.no_autoban,
				rate_limit: limitOf.get(Number(h.id)) || null,
			};
		});
	},

	/**
	 * Saves a proxy host's settings and deploys them.
	 *
	 * @param {Function} apply  internalSentinel.apply (change, undo)
	 */
	update: async (access, hostId, data, apply) => {
		await access.can("sentinel:update");
		const host = await proxyHostModel.query().where("is_deleted", 0).andWhere("id", hostId).first();
		if (!host) {
			throw new errs.ItemNotFoundError(hostId);
		}
		let clean;
		try {
			clean = { ...validate.underAttack(data), no_autoban: data.no_autoban === true };
		} catch (err) {
			throw toValidationError(err);
		}
		const before = await hostModel.query().where("proxy_host_id", hostId).first();
		await apply(
			async () => {
				if (before) {
					await hostModel.query().patchAndFetchById(before.id, clean);
				} else {
					await hostModel.query().insert({ proxy_host_id: hostId, ...clean });
				}
			},
			async () => {
				if (before) {
					await hostModel.query().patchAndFetchById(before.id, {
						under_attack: before.under_attack,
						config: before.config,
						no_autoban: before.no_autoban,
					});
				} else {
					await hostModel.query().where("proxy_host_id", hostId).delete();
				}
			},
		);
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "sentinel-host",
			object_id: hostId,
			meta: { domain_names: host.domain_names, ...clean },
		});
		internalUnderAttack.tick(true);
		return (await internalUnderAttack.list(access)).find((h) => Number(h.proxy_host_id) === Number(hostId));
	},

	/**
	 * Ends an automatic activation now.
	 */
	deactivate: async (access, hostId) => {
		await access.can("sentinel:update");
		const row = await hostModel.query().where("proxy_host_id", hostId).first();
		const duration = row ? validate.underAttack(row).config.duration_s : validate.UNDER_ATTACK.defDurationS;
		const t = ua.deactivate(loadState(), hostId, duration, Date.now());
		if (!t) {
			throw new errs.ValidationError("under attack mode is not automatically active for this host");
		}
		record([t]);
		saveState();
		await internalUnderAttack.push(true);
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "sentinel-host",
			object_id: hostId,
			meta: { under_attack_deactivated: true, host: t.host },
		});
		return true;
	},

	events: () => {
		loadState();
		return [...events].reverse();
	},

	syncStatus: () => ({
		ok: lastPush.ok,
		error: lastPush.error,
		at: lastPush.at ? new Date(lastPush.at).toISOString() : null,
	}),

	// ------------------------------------------------------------------ alerts

	getAlerts: async (access) => {
		await access.can("sentinel:get");
		const cfg = readAlerts();
		// the token is never sent back, only whether one is set
		return { ...cfg, token: "", has_token: cfg.token !== "", last: { ...lastAlert } };
	},

	setAlerts: async (access, data) => {
		await access.can("sentinel:update");
		const before = readAlerts();
		const input = { ...data };
		if (input.token === undefined || input.token === null || input.token === "") {
			// keep the stored token unless clear_token is set
			input.token = data.clear_token ? "" : before.token;
		}
		delete input.clear_token;
		let clean;
		try {
			clean = validate.alerts(input);
		} catch (err) {
			throw toValidationError(err);
		}
		fs.mkdirSync(PATHS.dir, { recursive: true });
		const tmp = `${ALERTS_FILE}.tmp`;
		fs.writeFileSync(tmp, JSON.stringify(clean), { mode: 0o600 });
		fs.renameSync(tmp, ALERTS_FILE);
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "sentinel-alerts",
			object_id: 0,
			meta: { enabled: clean.enabled, type: clean.type },
		});
		return internalUnderAttack.getAlerts(access);
	},

	testAlert: async (access) => {
		await access.can("sentinel:update");
		const cfg = readAlerts();
		if (!cfg.url) {
			throw new errs.ValidationError("save an alert address first");
		}
		try {
			await alerts.send(cfg, {
				title: "Nginx Proxy Manager test alert",
				text: "Sentinel alerts are working. You will get a message here when a host's under attack mode turns on or off.",
				event: "test",
			});
		} catch (err) {
			throw new errs.ValidationError(`the alert could not be sent: ${err.message}`);
		}
		lastAlert = { at: new Date().toISOString(), ok: true, error: "" };
		return true;
	},
};

export default internalUnderAttack;
