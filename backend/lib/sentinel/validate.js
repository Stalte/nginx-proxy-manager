/**
 * Validation and normalisation of Sentinel security rules and lists.
 *
 * The API schema checks the shape of a request; this checks what a schema can't (field
 * and operator combinations, networks, regular expressions, list references) and puts
 * values in the form the gateway expects. compile.js runs it again on stored rows before
 * they are written for the gateway.
 *
 * Ported from Corvus (control/internal/validate), Apache-2.0.
 */

import { isPublicIP, normalizeCidrs, parseIPv4, parseIPv6 } from "./ip.js";

export const LIMITS = {
	maxRules: 200,
	maxGroups: 10,
	maxConditions: 10,
	maxValueLen: 1024,
	maxValues: 1000,
	maxRegexLen: 512,
	maxIPListItems: 50000, // lists edited by hand (stored in the database)
	maxIPFeedItems: 5000000, // lists fed from a URL (stored as a range file)
	maxUAListItems: 10000, // User-Agent lists are matched by a linear scan
	minUAEntryLen: 3,
	maxUAEntryLen: 256,
	minRefreshS: 300,
	maxRefreshS: 7 * 86400,
	defRefreshS: 3600,
	maxURLLen: 2048,
};

export const ACTIONS = ["block", "allow", "log", "challenge"];
export const BLOCK_STATUS = [401, 403, 404, 410, 429, 444];

const STRING_OPS = new Set([
	"eq",
	"ne",
	"contains",
	"not_contains",
	"starts_with",
	"ends_with",
	"matches",
	"not_matches",
	"in",
	"not_in",
]);
const SET_OPS = new Set(["in", "not_in"]);

// Fields a condition may test: set (in / not_in), str (string operators), exists
// Browser challenge settings (rule action "challenge" and the "under attack" mode),
// the ranges of /etc/nginx/lua/corvus/challenge.lua
export const CHALLENGE = {
	modes: ["js", "cookie"],
	binds: ["ip", "ip_ua"],
	minBits: 12,
	maxBits: 24,
	defBits: 16,
	minTTL: 300,
	maxTTL: 7 * 86400,
	defTTL: 86400,
};

// "Under attack" mode (Corvus control/internal/validate/underattack.go)
export const UNDER_ATTACK = {
	modes: ["off", "on", "auto"],
	defTTL: 3600,
	defRPS: 200,
	defBlockedPct: 50,
	defWindowS: 30,
	defDurationS: 900,
	minWindowS: 10,
	maxWindowS: 600,
	minDurationS: 60,
	maxDurationS: 86400,
};

export const FIELDS = {
	"ip.src": { set: true },
	"ip.country": { set: true },
	"http.method": { set: true },
	"http.scheme": { set: true },
	"http.host": { str: true },
	"http.path": { str: true },
	"http.query": { str: true },
	"http.user_agent": { str: true, exists: true },
	// User-Agent contains (case-insensitive) any entry of a User-Agent list
	"http.user_agent_list": { set: true },
	"http.referer": { str: true, exists: true },
	"http.header": { str: true, exists: true },
};

const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
const COUNTRY_RE = /^[A-Z]{2}$/;
const METHOD_RE = /^[A-Z]{1,16}$/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what it rejects
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;

export class ValidationErrors extends Error {
	constructor() {
		super("validation failed");
		this.fields = [];
	}

	add(field, message) {
		this.fields.push({ field, message });
	}

	throwIfAny() {
		if (this.fields.length) {
			this.message = this.fields.map((f) => `${f.field}: ${f.message}`).join("; ");
			throw this;
		}
	}
}

/**
 * "list:<id>" → id, or 0
 *
 * @param   {string} v
 * @returns {number}
 */
export const listRef = (v) => {
	const m = typeof v === "string" ? v.match(/^list:([1-9][0-9]{0,9})$/) : null;
	return m ? Number(m[1]) : 0;
};

export const displayName = (s, max) => typeof s === "string" && s !== "" && [...s].length <= max && !CONTROL_RE.test(s);

/**
 * Validates a regular expression for a rule: the subset that PCRE (nginx) and JavaScript
 * read the same way, without backreferences, lookaround or PCRE verbs.
 *
 * @param {string} p
 */
export const ruleRegex = (p) => {
	if (p.length > LIMITS.maxRegexLen) {
		throw new Error(`regular expression must be at most ${LIMITS.maxRegexLen} characters`);
	}
	if (p.includes("\\C") || p.includes("(*") || /\(\?<?[=!]/.test(p) || /\\[1-9k]/.test(p)) {
		throw new Error("unsupported regular expression construct (no lookaround, backreferences or verbs)");
	}
	try {
		new RegExp(p, "u");
	} catch (err) {
		throw new Error(`invalid regular expression: ${err.message}`);
	}
};

/**
 * @param   {Object}   c         condition {field, name, operator, value[], ci}
 * @param   {Function} listKind  id → "ip" | "user_agent" | "" (missing)
 * @returns {Object}             normalised condition
 */
const condition = (c, listKind) => {
	const field = c?.field;
	const f = FIELDS[field];
	if (!f) {
		throw new Error(`unknown field "${String(field).slice(0, 40)}"`);
	}
	const out = { field, operator: c.operator, value: [] };
	if (c.ci) {
		out.ci = true;
	}
	if (field === "http.header") {
		const name = String(c.name || "")
			.trim()
			.toLowerCase();
		if (!HEADER_NAME_RE.test(name)) {
			throw new Error("a valid header name is required");
		}
		out.name = name;
	}
	const op = c.operator;
	if ((op === "exists" || op === "not_exists") && f.exists) {
		return out;
	}
	if ((f.set && !SET_OPS.has(op)) || (f.str && !STRING_OPS.has(op))) {
		throw new Error(`operator "${String(op).slice(0, 20)}" is not valid for ${field}`);
	}
	let vals = [];
	for (const raw of Array.isArray(c.value) ? c.value : []) {
		const v = String(raw).trim();
		if (v === "") {
			continue;
		}
		if (v.length > LIMITS.maxValueLen || /[\0\r\n]/.test(v)) {
			throw new Error(`values must be single-line and at most ${LIMITS.maxValueLen} characters`);
		}
		vals.push(v);
	}
	if (!vals.length) {
		throw new Error("a value is required");
	}
	if (vals.length > LIMITS.maxValues) {
		throw new Error(`at most ${LIMITS.maxValues} values`);
	}
	if (!SET_OPS.has(op) && vals.length !== 1) {
		throw new Error(`operator "${op}" takes exactly one value`);
	}
	switch (field) {
		case "ip.src": {
			const cidrs = [];
			const refs = [];
			for (const v of vals) {
				const id = listRef(v);
				if (id) {
					checkListRef(id, "ip", listKind);
					refs.push(`list:${id}`);
				} else {
					cidrs.push(v);
				}
			}
			vals = [...normalizeCidrs(cidrs), ...new Set(refs)];
			if (!vals.length) {
				throw new Error("a value is required");
			}
			break;
		}
		case "http.user_agent_list":
			for (const v of vals) {
				const id = listRef(v);
				if (!id) {
					throw new Error("select a User-Agent list");
				}
				checkListRef(id, "user_agent", listKind);
			}
			break;
		case "ip.country":
			vals = vals.map((v) => {
				const u = v.toUpperCase();
				if (!COUNTRY_RE.test(u)) {
					throw new Error(`invalid country code "${v.slice(0, 10)}"`);
				}
				return u;
			});
			break;
		case "http.method":
			vals = vals.map((v) => {
				const u = v.toUpperCase();
				if (!METHOD_RE.test(u)) {
					throw new Error(`invalid method "${v.slice(0, 20)}"`);
				}
				return u;
			});
			break;
		case "http.scheme":
			vals = vals.map((v) => {
				const l = v.toLowerCase();
				if (l !== "http" && l !== "https") {
					throw new Error("scheme must be http or https");
				}
				return l;
			});
			break;
		default:
	}
	if (op === "matches" || op === "not_matches") {
		ruleRegex(vals[0]);
	}
	out.value = vals;
	return out;
};

const checkListRef = (id, want, listKind) => {
	if (!listKind) {
		return;
	}
	const k = listKind(id);
	if (!k) {
		throw new Error(`list ${id} does not exist`);
	}
	if (k !== want) {
		throw new Error(want === "ip" ? `list ${id} is not an IP list` : `list ${id} is not a User-Agent list`);
	}
};

/**
 * Validates and normalises a security rule.
 *
 * @param   {Object}   r           rule payload (name, description, enabled, action, status_code, scope, host_ids, expression)
 * @param   {Function} [listKind]  id → list kind ("" when missing)
 * @param   {Function} [hostExists] id → whether the proxy host exists
 * @returns {Object}               normalised rule fields
 * @throws  {ValidationErrors}
 */
export const securityRule = (r, listKind, hostExists) => {
	const errs = new ValidationErrors();
	const out = {
		name: String(r.name ?? "").trim(),
		description: String(r.description ?? "").trim(),
		enabled: r.enabled !== false,
		action: r.action,
		status_code: 403,
		challenge: null,
		scope: r.scope || "all",
		host_ids: [],
		expression: { groups: [] },
	};
	if (!displayName(out.name, 100)) {
		errs.add("name", "name must be 1-100 characters");
	}
	if ([...out.description].length > 500 || out.description.includes("\0")) {
		errs.add("description", "description must be at most 500 characters");
	}
	if (out.action === "block") {
		const sc = r.status_code ? Number(r.status_code) : 403;
		if (!BLOCK_STATUS.includes(sc)) {
			errs.add("status_code", `status code must be one of ${BLOCK_STATUS.join(", ")}`);
		}
		out.status_code = sc;
	} else if (out.action === "challenge") {
		out.challenge = challengeSettings(r.challenge, errs, "challenge");
	} else if (!ACTIONS.includes(out.action)) {
		errs.add("action", `action must be ${ACTIONS.join(", ")}`);
	}
	if (out.scope === "hosts") {
		const ids = [...new Set((r.host_ids || []).map((h) => Number(h)))];
		if (!ids.length) {
			errs.add("host_ids", "select at least one proxy host");
		}
		for (const h of ids) {
			if (!Number.isInteger(h) || h < 1 || (hostExists && !hostExists(h))) {
				errs.add("host_ids", `proxy host ${h} does not exist`);
			}
		}
		out.host_ids = ids;
	} else if (out.scope !== "all") {
		errs.add("scope", "scope must be all or hosts");
	}
	const groups = r.expression?.groups;
	if (!Array.isArray(groups) || !groups.length) {
		errs.add("expression", "add at least one condition");
	} else {
		if (groups.length > LIMITS.maxGroups) {
			errs.add("expression", `at most ${LIMITS.maxGroups} OR groups`);
		}
		groups.slice(0, LIMITS.maxGroups).forEach((g, gi) => {
			if (!Array.isArray(g) || !g.length) {
				errs.add("expression", "empty condition group");
				return;
			}
			if (g.length > LIMITS.maxConditions) {
				errs.add("expression", `at most ${LIMITS.maxConditions} conditions per group`);
			}
			const cg = [];
			g.slice(0, LIMITS.maxConditions).forEach((c, ci) => {
				try {
					cg.push(condition(c, listKind));
				} catch (err) {
					errs.add(`expression.groups.${gi}.${ci}`, err.message);
				}
			});
			out.expression.groups.push(cg);
		});
	}
	errs.throwIfAny();
	return out;
};

/**
 * One User-Agent list entry: a plain, case-insensitive substring.
 *
 * @param {string} v
 */
export const uaEntry = (v) => {
	if (v.length < LIMITS.minUAEntryLen || v.length > LIMITS.maxUAEntryLen) {
		throw new Error(
			`User-Agent entry "${v.slice(0, 40)}" must be ${LIMITS.minUAEntryLen}-${LIMITS.maxUAEntryLen} characters`,
		);
	}
	if (CONTROL_RE.test(v)) {
		throw new Error(`User-Agent entry "${v.slice(0, 40)}" contains control characters`);
	}
};

/**
 * Trims, validates and de-duplicates (case-insensitively) User-Agent entries.
 *
 * @param   {string[]} input
 * @returns {string[]}
 */
export const normalizeUAEntries = (input) => {
	const out = [];
	const seen = new Set();
	for (const raw of input || []) {
		const v = String(raw).trim();
		if (v === "") {
			continue;
		}
		uaEntry(v);
		const k = v.toLowerCase();
		if (!seen.has(k)) {
			seen.add(k);
			out.push(v);
		}
	}
	return out;
};

/**
 * Checks the syntax of a list feed URL: https only, a host name, no credentials, not a
 * local address. Where it points is checked again when connecting (feeds.js).
 *
 * @param {string} raw
 */
export const feedURL = (raw) => {
	if (raw.length > LIMITS.maxURLLen) {
		throw new Error(`URL must be at most ${LIMITS.maxURLLen} characters`);
	}
	if (/\s/.test(raw)) {
		throw new Error("invalid URL");
	}
	let u;
	try {
		u = new URL(raw);
	} catch {
		throw new Error("invalid URL");
	}
	if (u.protocol !== "https:") {
		throw new Error("only https:// URLs are allowed");
	}
	if (u.username || u.password) {
		throw new Error("credentials in the URL are not allowed");
	}
	const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
	if (!host) {
		throw new Error("invalid URL");
	}
	if ((parseIPv4(host) !== null || parseIPv6(host) !== null) && !isPublicIP(host)) {
		throw new Error("the URL must point to a public address");
	}
	if (host === "localhost" || host.endsWith(".localhost")) {
		throw new Error("the URL must point to a public address");
	}
};

/**
 * Validates and normalises a list.
 *
 * @param   {Object} l  list payload (name, description, kind, source_url, refresh_s, items)
 * @returns {Object}    normalised list fields
 * @throws  {ValidationErrors}
 */
export const list = (l) => {
	const errs = new ValidationErrors();
	const out = {
		name: String(l.name ?? "").trim(),
		description: String(l.description ?? "").trim(),
		kind: l.kind || "ip",
		source_url: String(l.source_url ?? "").trim(),
		refresh_s: Number(l.refresh_s) || LIMITS.defRefreshS,
		items: [],
	};
	if (!displayName(out.name, 64)) {
		errs.add("name", "name must be 1-64 characters");
	}
	if ([...out.description].length > 500) {
		errs.add("description", "description must be at most 500 characters");
	}
	if (out.source_url) {
		try {
			feedURL(out.source_url);
		} catch (err) {
			errs.add("source_url", err.message);
		}
		if (out.refresh_s < LIMITS.minRefreshS || out.refresh_s > LIMITS.maxRefreshS) {
			errs.add("refresh_s", "refresh interval must be 5 minutes to 7 days");
		}
	}
	const items = out.source_url ? [] : l.items || [];
	if (out.kind === "ip") {
		if (items.length > LIMITS.maxIPListItems) {
			errs.add("items", `at most ${LIMITS.maxIPListItems} entries`);
		} else {
			try {
				out.items = normalizeCidrs(items);
			} catch (err) {
				errs.add("items", err.message);
			}
		}
	} else if (out.kind === "user_agent") {
		if (items.length > LIMITS.maxUAListItems) {
			errs.add("items", `at most ${LIMITS.maxUAListItems} entries`);
		} else {
			try {
				out.items = normalizeUAEntries(items);
			} catch (err) {
				errs.add("items", err.message);
			}
		}
	} else {
		errs.add("kind", "kind must be ip or user_agent");
	}
	errs.throwIfAny();
	return out;
};

const intIn = (v, def, min, max) => {
	const n = v === undefined || v === null || v === "" ? def : Number(v);
	return Number.isInteger(n) && n >= min && n <= max ? n : null;
};

/**
 * Normalises browser challenge settings {mode, difficulty, ttl, bind}; problems are
 * added to errs under prefix.
 */
export const challengeSettings = (c, errs, prefix, defTTL = CHALLENGE.defTTL) => {
	const src = c && typeof c === "object" ? c : {};
	const out = {
		mode: src.mode || "js",
		difficulty: intIn(src.difficulty, CHALLENGE.defBits, CHALLENGE.minBits, CHALLENGE.maxBits),
		ttl: intIn(src.ttl, defTTL, CHALLENGE.minTTL, CHALLENGE.maxTTL),
		bind: src.bind || "ip",
	};
	if (!CHALLENGE.modes.includes(out.mode)) {
		errs.add(`${prefix}.mode`, "challenge type must be js or cookie");
	}
	if (out.difficulty === null) {
		errs.add(`${prefix}.difficulty`, `difficulty must be ${CHALLENGE.minBits}-${CHALLENGE.maxBits} bits`);
	}
	if (out.ttl === null) {
		errs.add(`${prefix}.ttl`, "pass lifetime must be 300-604800 seconds (5 minutes to 7 days)");
	}
	if (!CHALLENGE.binds.includes(out.bind)) {
		errs.add(`${prefix}.bind`, "binding must be ip or ip_ua");
	}
	return out;
};

/**
 * Validates a proxy host's "under attack" settings. Parameters are checked whatever the
 * mode, so switching modes later never meets a stored value the gateway cannot use.
 *
 * @param   {Object} h  {under_attack, config: {mode, difficulty, ttl, bind, rps, blocked_pct, window_s, duration_s}}
 * @returns {Object}    normalised {under_attack, config}
 * @throws  {ValidationErrors}
 */
export const underAttack = (h) => {
	const errs = new ValidationErrors();
	const mode = h?.under_attack || "off";
	if (!UNDER_ATTACK.modes.includes(mode)) {
		errs.add("under_attack", "under attack mode must be off, on or auto");
	}
	const c = h?.config && typeof h.config === "object" ? h.config : {};
	const config = challengeSettings(c, errs, "config", UNDER_ATTACK.defTTL);
	const rps = c.rps === undefined || c.rps === null || c.rps === "" ? UNDER_ATTACK.defRPS : Number(c.rps);
	if (!Number.isFinite(rps) || rps < 1 || rps > 1e6) {
		errs.add("config.rps", "requests per second must be 1-1000000");
	}
	const pct =
		c.blocked_pct === undefined || c.blocked_pct === null || c.blocked_pct === ""
			? UNDER_ATTACK.defBlockedPct
			: Number(c.blocked_pct);
	if (!Number.isFinite(pct) || pct < 0 || pct > 100) {
		errs.add("config.blocked_pct", "blocked share must be 0-100 percent (0 = not used)");
	}
	const windowS = intIn(c.window_s, UNDER_ATTACK.defWindowS, UNDER_ATTACK.minWindowS, UNDER_ATTACK.maxWindowS);
	if (windowS === null) {
		errs.add(
			"config.window_s",
			`measuring window must be ${UNDER_ATTACK.minWindowS}-${UNDER_ATTACK.maxWindowS} seconds`,
		);
	}
	const durationS = intIn(
		c.duration_s,
		UNDER_ATTACK.defDurationS,
		UNDER_ATTACK.minDurationS,
		UNDER_ATTACK.maxDurationS,
	);
	if (durationS === null) {
		errs.add(
			"config.duration_s",
			`activation period must be ${UNDER_ATTACK.minDurationS}-${UNDER_ATTACK.maxDurationS} seconds`,
		);
	}
	errs.throwIfAny();
	return {
		under_attack: mode,
		config: { ...config, rps, blocked_pct: pct, window_s: windowS, duration_s: durationS },
	};
};

export const ALERT_TYPES = ["webhook", "discord", "slack", "ntfy", "gotify"];

/**
 * Validates the alert settings {enabled, type, url, token}. The URL is chosen by an
 * administrator and may point at a service on the local network (ntfy, Gotify).
 */
export const alerts = (a) => {
	const errs = new ValidationErrors();
	const out = {
		enabled: a?.enabled === true,
		type: a?.type || "webhook",
		url: String(a?.url ?? "").trim(),
		token: String(a?.token ?? "").trim(),
	};
	if (!ALERT_TYPES.includes(out.type)) {
		errs.add("type", `type must be one of ${ALERT_TYPES.join(", ")}`);
	}
	if (out.url) {
		let u = null;
		try {
			u = new URL(out.url);
		} catch {
			// reported below
		}
		if (!u || !["http:", "https:"].includes(u.protocol) || out.url.length > LIMITS.maxURLLen) {
			errs.add("url", "URL must be an http:// or https:// address");
		}
	} else if (out.enabled) {
		errs.add("url", "enter the address alerts are sent to");
	}
	if (out.token.length > 256 || CONTROL_RE.test(out.token)) {
		errs.add("token", "token must be at most 256 characters");
	}
	errs.throwIfAny();
	return out;
};
