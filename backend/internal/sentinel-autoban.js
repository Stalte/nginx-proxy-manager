import fs from "node:fs";
import errs from "../lib/error.js";
import * as ab from "../lib/sentinel/autoban.js";
import { PATHS } from "../lib/sentinel/compile.js";
import { statusRequest } from "../lib/sentinel/status.js";
import { ValidationErrors } from "../lib/sentinel/validate.js";
import { sentinel as logger } from "../logger.js";
import banModel from "../models/sentinel_ban.js";
import internalAuditLog from "./audit-log.js";

const SETTINGS_FILE = `${PATHS.dir}/autoban.json`;
const TICK_MS = 15 * 1000;
const FULL_PUSH_MS = 5 * 60 * 1000;
const PRUNE_MS = 3600 * 1000;
const MAX_MANUAL_S = ab.MAX_DURATION_S;
const MAX_BANS = 50000;

let timer = null;
let running = false;
const acks = {};
let lastPush = { at: 0, hash: "", ok: true, error: "" };
let lastPrune = 0;
let epoch = "";

const toValidationError = (err) => (err instanceof ValidationErrors ? new errs.ValidationError(err.message) : err);

const nowS = () => Math.floor(Date.now() / 1000);

const readSettings = () => {
	try {
		return ab.settings(JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8")));
	} catch {
		return ab.settings({});
	}
};

const isActive = (b, now) => b.expires_at === null || b.expires_at === undefined || Number(b.expires_at) > now;

const view = (b, now) => ({
	id: b.id,
	ip: b.ip,
	reason: b.reason,
	source: b.source,
	offenses: b.offenses,
	created_on: b.created_on,
	modified_on: b.modified_on,
	expires_at: b.expires_at === null || b.expires_at === undefined ? null : Number(b.expires_at),
	active: isActive(b, now),
});

const activeBans = async (now) => (await banModel.query().limit(MAX_BANS * 2)).filter((b) => isActive(b, now));

const internalAutoban = {
	/**
	 * Records the gateway's pending bans and acknowledges them with the next push. Records
	 * that are not stored (turned off, exempt, already banned, invalid) are acknowledged
	 * too, so the gateway drops its local ban.
	 */
	recordHits: async (hits, set, now) => {
		const active = new Set((await activeBans(now)).map((b) => b.ip));
		let changed = false;
		for (const h of hits) {
			if (!h || typeof h.ip !== "string" || typeof h.id !== "string") continue;
			const key = ab.hitKey(h.ip);
			const kindOn = h.kind === "detections" ? set.detections : set.bad_behaviour;
			if (!key || !set.enabled || !kindOn || active.has(key) || ab.exemptKey(key, set.exempt)) {
				acks[h.ip] = h.id;
				continue;
			}
			try {
				const old = await banModel.query().where("ip", key).first();
				const offenses = old ? Number(old.offenses) + 1 : 1;
				const until = ab.banUntil(set, offenses, now * 1000);
				const row = {
					reason: ab.hitReason(h).slice(0, 500),
					source: "auto",
					offenses,
					expires_at: until === null ? null : Math.floor(until / 1000),
				};
				if (old) {
					await banModel.query().patch(row).where("id", old.id);
				} else {
					await banModel.query().insert({ ip: key, ...row });
				}
				active.add(key);
				acks[h.ip] = h.id;
				changed = true;
				logger.warn(
					`Banned ${key} automatically (offense ${offenses}, ${row.expires_at === null ? "permanent" : `until ${new Date(row.expires_at * 1000).toISOString()}`}): ${row.reason}`,
				);
			} catch (err) {
				// not acknowledged: comes back next round
				logger.error(`Automatic ban of ${key} not stored: ${err.message}`);
			}
		}
		return changed;
	},

	/**
	 * Pushes the active ban list and the gateway settings when they changed, when bans are
	 * waiting for their acknowledgement, and at least every five minutes.
	 */
	push: async (force = false) => {
		const now = nowS();
		const set = readSettings();
		const ips = {};
		for (const b of await activeBans(now)) {
			ips[ab.gatewayKey(b.ip)] = b.expires_at === null || b.expires_at === undefined ? 0 : Number(b.expires_at);
		}
		const payload = { ips, bb: ab.gatewayConfig(set), ack: { ...acks } };
		const hash = JSON.stringify(payload);
		const due =
			force ||
			Object.keys(acks).length > 0 ||
			hash !== lastPush.hash ||
			!lastPush.ok ||
			Date.now() - lastPush.at >= FULL_PUSH_MS;
		if (!due) return;
		try {
			await statusRequest("/bans", {
				method: "PUT",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ ...payload, now }),
			});
			for (const [ip, id] of Object.entries(payload.ack)) {
				if (acks[ip] === id) delete acks[ip];
			}
			lastPush = { at: Date.now(), hash, ok: true, error: "" };
		} catch (err) {
			lastPush = { at: Date.now(), hash: "", ok: false, error: err.message };
		}
	},

	tick: async (force = false) => {
		if (running) return;
		running = true;
		try {
			const set = readSettings();
			let restarted = false;
			try {
				const res = await statusRequest("/bad-behaviour");
				const out = await res.json();
				if (out.epoch && epoch && out.epoch !== epoch) restarted = true;
				epoch = out.epoch || epoch;
				if (Array.isArray(out.hits) && out.hits.length) {
					await internalAutoban.recordHits(out.hits, set, nowS());
				}
			} catch (err) {
				logger.debug?.(`Sentinel ban poll failed: ${err.message}`);
			}
			await internalAutoban.push(force || restarted);
			if (Date.now() - lastPrune > PRUNE_MS) {
				lastPrune = Date.now();
				// offense history is kept for 30 days after a ban ended
				const old = nowS() - ab.MAX_DURATION_S;
				await banModel.query().whereNotNull("expires_at").andWhere("expires_at", "<", old).delete();
			}
		} catch (err) {
			logger.error(`Automatic bans round failed: ${err.message}`);
		} finally {
			running = false;
		}
	},

	start: () => {
		if (timer) return;
		setTimeout(() => internalAutoban.tick(true), 6000);
		timer = setInterval(() => internalAutoban.tick(), TICK_MS);
	},

	syncStatus: () => ({
		ok: lastPush.ok,
		error: lastPush.error,
		at: lastPush.at ? new Date(lastPush.at).toISOString() : null,
	}),

	// ------------------------------------------------------------------ API

	list: async (access) => {
		await access.can("sentinel:list");
		const now = nowS();
		const rows = await banModel
			.query()
			.orderBy("modified_on", "desc")
			.limit(MAX_BANS * 2);
		// active bans first, then the ones that ended (offense history)
		return rows
			.map((b) => view(b, now))
			.sort((a, b) => Number(b.active) - Number(a.active))
			.slice(0, 2000);
	},

	/**
	 * Bans an address by hand: {ip, reason, duration_s (0 = permanent)}.
	 */
	ban: async (access, data) => {
		await access.can("sentinel:update");
		const key = ab.banKey(data.ip);
		if (!key) {
			throw new errs.ValidationError("enter an IPv4 or IPv6 address");
		}
		const set = readSettings();
		if (ab.exemptKey(key, [])) {
			throw new errs.ValidationError("loopback addresses cannot be banned");
		}
		if (ab.exemptKey(key, set.exempt)) {
			throw new errs.ValidationError("this address is in the exempt networks of the automatic bans");
		}
		const duration = Number(data.duration_s || 0);
		if (!Number.isInteger(duration) || duration < 0 || duration > MAX_MANUAL_S) {
			throw new errs.ValidationError("duration must be up to 30 days (0 = permanent)");
		}
		const reason =
			String(data.reason ?? "")
				.trim()
				.slice(0, 500) || "banned by an administrator";
		const now = nowS();
		const row = { reason, source: "manual", expires_at: duration ? now + duration : null };
		const old = await banModel.query().where("ip", key).first();
		if (old) {
			await banModel.query().patch(row).where("id", old.id);
		} else {
			await banModel.query().insert({ ip: key, offenses: 0, ...row });
		}
		await internalAuditLog.add(access, {
			action: "created",
			object_type: "sentinel-ban",
			object_id: 0,
			meta: { ip: key, reason, expires_at: row.expires_at },
		});
		await internalAutoban.push(true);
		return view(await banModel.query().where("ip", key).first(), now);
	},

	/**
	 * Lifts a ban now. The offense count stays, so a client that comes back is banned for
	 * longer.
	 */
	lift: async (access, id) => {
		await access.can("sentinel:update");
		const b = await banModel.query().findById(id);
		if (!b) {
			throw new errs.ItemNotFoundError(id);
		}
		await banModel.query().patch({ expires_at: nowS() }).where("id", id);
		await internalAuditLog.add(access, {
			action: "deleted",
			object_type: "sentinel-ban",
			object_id: 0,
			meta: { ip: b.ip },
		});
		await internalAutoban.push(true);
		return true;
	},

	getSettings: async (access) => {
		await access.can("sentinel:get");
		return readSettings();
	},

	setSettings: async (access, data) => {
		await access.can("sentinel:update");
		let clean;
		try {
			clean = ab.settings(data);
		} catch (err) {
			throw toValidationError(err);
		}
		fs.mkdirSync(PATHS.dir, { recursive: true });
		const tmp = `${SETTINGS_FILE}.tmp`;
		fs.writeFileSync(tmp, JSON.stringify(clean));
		fs.renameSync(tmp, SETTINGS_FILE);
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "sentinel-autoban",
			object_id: 0,
			meta: clean,
		});
		await internalAutoban.push(true);
		return clean;
	},

	count: async () => (await activeBans(nowS())).length,
};

export default internalAutoban;
