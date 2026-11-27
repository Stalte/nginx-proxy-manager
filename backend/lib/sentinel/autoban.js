/**
 * Automatic bans: clients that keep getting error responses ("bad behaviour", e.g.
 * scanners probing for files) or keep being refused by Sentinel (security detections) are
 * banned, for longer each time they come back.
 *
 * The gateway counts both per client in its shared memory and bans the client there as
 * soon as a threshold is reached (/etc/nginx/lua/corvus/rules.lua, npm_log). The backend
 * polls those pending bans from the loopback status port, records them with escalation
 * and pushes the authoritative ban list back (internal/sentinel-autoban.js).
 *
 * Ported from Corvus (control/internal/autoban), Apache-2.0.
 */

import { encodeNet, normalizeCidrs, parseEntry, parseIPv4, parseIPv6, v4String, v6String } from "./ip.js";
import { ValidationErrors } from "./validate.js";

export const MAX_DURATION_S = 30 * 86400;
export const DEFAULT_CODES = [400, 401, 403, 404, 405, 429, 444];
export const LOOPBACK = ["127.0.0.0/8", "::1/128"];

export const DEFAULTS = {
	enabled: false,
	// security detections (requests Sentinel refused) per client
	detections: true,
	threshold: 20,
	window_s: 600,
	// error responses per client and host
	bad_behaviour: true,
	bad_behaviour_codes: DEFAULT_CODES,
	bad_behaviour_threshold: 30,
	bad_behaviour_window_s: 60,
	// first ban, doubled for each repeat offense up to max_duration_s
	duration_s: 900,
	max_duration_s: 7 * 86400,
	// permanent from this offense on; 0 = never
	permanent_after: 0,
	exempt: [],
};

const int = (v, def) => (v === undefined || v === null || v === "" ? def : Number(v));

/**
 * Validates and normalises the automatic-ban settings.
 *
 * @throws {ValidationErrors}
 */
export const settings = (input) => {
	const s = { ...DEFAULTS, ...(input && typeof input === "object" ? input : {}) };
	const errs = new ValidationErrors();
	const out = {
		enabled: s.enabled === true,
		detections: s.detections !== false,
		threshold: int(s.threshold, DEFAULTS.threshold),
		window_s: int(s.window_s, DEFAULTS.window_s),
		bad_behaviour: s.bad_behaviour !== false,
		bad_behaviour_codes: [],
		bad_behaviour_threshold: int(s.bad_behaviour_threshold, DEFAULTS.bad_behaviour_threshold),
		bad_behaviour_window_s: int(s.bad_behaviour_window_s, DEFAULTS.bad_behaviour_window_s),
		duration_s: int(s.duration_s, DEFAULTS.duration_s),
		max_duration_s: int(s.max_duration_s, DEFAULTS.max_duration_s),
		permanent_after: int(s.permanent_after, 0),
		exempt: [],
	};
	const range = (k, min, max, msg) => {
		if (!Number.isInteger(out[k]) || out[k] < min || out[k] > max) errs.add(k, msg);
	};
	range("threshold", 3, 100000, "threshold must be 3-100000");
	range("window_s", 60, 86400, "window must be 60-86400 seconds");
	range("bad_behaviour_threshold", 3, 100000, "error response threshold must be 3-100000");
	range("bad_behaviour_window_s", 10, 3600, "error response window must be 10-3600 seconds");
	range("duration_s", 60, MAX_DURATION_S, "ban duration must be 60 seconds to 30 days");
	if (
		!Number.isInteger(out.max_duration_s) ||
		out.max_duration_s < out.duration_s ||
		out.max_duration_s > MAX_DURATION_S
	) {
		errs.add("max_duration_s", "maximum ban duration must be between the first ban duration and 30 days");
	}
	if (
		!Number.isInteger(out.permanent_after) ||
		(out.permanent_after !== 0 && (out.permanent_after < 2 || out.permanent_after > 100))
	) {
		errs.add("permanent_after", "permanent ban must start at offense 2-100 (0 = never)");
	}
	const codes = Array.isArray(s.bad_behaviour_codes) ? s.bad_behaviour_codes : DEFAULT_CODES;
	const seen = new Set();
	for (const c of codes) {
		const n = Number(c);
		if (!Number.isInteger(n) || n < 400 || n > 599) {
			errs.add("bad_behaviour_codes", "status codes must be 400-599");
			break;
		}
		seen.add(n);
	}
	out.bad_behaviour_codes = [...seen].sort((a, b) => a - b);
	if (out.bad_behaviour && !out.bad_behaviour_codes.length) {
		errs.add("bad_behaviour_codes", "choose at least one status code");
	}
	if (out.bad_behaviour_codes.length > 30) {
		errs.add("bad_behaviour_codes", "at most 30 status codes");
	}
	try {
		out.exempt = normalizeCidrs(Array.isArray(s.exempt) ? s.exempt : []);
		if (out.exempt.length > 1000) errs.add("exempt", "at most 1000 exempt networks");
	} catch (err) {
		errs.add("exempt", err.message);
	}
	errs.throwIfAny();
	return out;
};

/**
 * When the ban for the given offense ends (ms); null = permanent. The first ban lasts
 * duration_s and doubles with each repeat offense up to max_duration_s.
 */
export const banUntil = (set, offenses, now) => {
	if (set.permanent_after > 0 && offenses >= set.permanent_after) {
		return null;
	}
	const limit = Math.min(set.max_duration_s || MAX_DURATION_S, MAX_DURATION_S);
	let d = set.duration_s;
	for (let i = 1; i < offenses && d < limit; i++) {
		d *= 2;
	}
	return now + Math.min(d, limit) * 1000;
};

const V6_64_MASK = ((1n << 64n) - 1n) << 64n;

/**
 * What a ban of ip covers: the IPv4 address, or the IPv6 /64 as a CIDR
 * ("2001:db8:1:2::/64"). "" for an invalid address.
 */
export const banKey = (ip) => {
	const s = String(ip ?? "").trim();
	const v4 = parseIPv4(s);
	if (v4 !== null) {
		return v4String(v4);
	}
	const net = s.includes("/") ? parseEntry(s) : null;
	if (net && net.v === 6 && net.prefix === 64) {
		return `${v6String(net.first)}/64`;
	}
	const v6 = s.includes("/") ? null : parseIPv6(s);
	if (v6 === null) {
		return "";
	}
	return `${v6String(v6 & V6_64_MASK)}/64`;
};

/**
 * The gateway's ban-table key for a stored ban: the IPv4 address, or for an IPv6 /64 its
 * first four groups in full ("2001:0db8:0001:0002"), as corvus/ipkey.lua derives it.
 */
export const gatewayKey = (key) => {
	if (!key.endsWith("/64")) {
		return key;
	}
	const v6 = parseIPv6(key.slice(0, -3));
	const groups = [];
	for (let i = 7; i >= 4; i--) {
		groups.push(
			Number((v6 >> BigInt(i * 16)) & 0xffffn)
				.toString(16)
				.padStart(4, "0"),
		);
	}
	return groups.join(":");
};

/**
 * Reads the client of a gateway record (an IPv4 address, or an IPv6 /64 in the gateway's
 * form) and returns its ban key, or "".
 */
export const hitKey = (s) => {
	const str = String(s ?? "");
	if (/^[0-9a-f]{4}(:[0-9a-f]{4}){3}$/.test(str)) {
		return banKey(`${str}::`);
	}
	return banKey(str);
};

const keyRange = (key) => {
	const n = parseEntry(key.includes("/") ? key : key.includes(":") ? `${key}/128` : `${key}/32`);
	return n || null;
};

/**
 * Whether a ban of key would cover loopback or overlap an exempt network.
 */
export const exemptKey = (key, exempt) => {
	const k = keyRange(key);
	if (!k) return true;
	for (const c of [...LOOPBACK, ...(exempt || [])]) {
		const n = parseEntry(c);
		if (n && n.v === k.v && n.first <= k.last && k.first <= n.last) {
			return true;
		}
	}
	return false;
};

/**
 * Ban reason of a gateway record, e.g. "12×404, 3×403 on example.com in 60 s".
 */
export const hitReason = (h) => {
	const host = h.host || "?";
	if (h.kind === "detections") {
		return `${Number(h.counts?.blocked) || 0} requests refused by Sentinel on ${host} in ${h.window} s`;
	}
	const parts = Object.entries(h.counts || {})
		.filter(([, n]) => Number(n) > 0)
		.sort((a, b) => Number(b[1]) - Number(a[1]) || a[0].localeCompare(b[0]))
		.map(([code, n]) => `${n}×${code}`);
	return `${parts.join(", ") || "error responses"} on ${host} in ${h.window} s`;
};

/**
 * Settings the gateway applies (pushed with the ban list, "bb").
 */
export const gatewayConfig = (set) => {
	const on = set.enabled && (set.bad_behaviour || set.detections);
	if (!on) {
		return { enabled: false };
	}
	const cfg = {
		enabled: true,
		// an empty list turns the error-response detector off
		codes: set.bad_behaviour ? set.bad_behaviour_codes : [],
		threshold: set.bad_behaviour_threshold,
		window: set.bad_behaviour_window_s,
		duration: set.duration_s,
		exempt: [...LOOPBACK, ...set.exempt].map(encodeNet),
	};
	if (set.detections) {
		cfg.det = { threshold: set.threshold, window: set.window_s };
	}
	return cfg;
};
