/**
 * Rate limit policies: nginx limit_req (requests per second, with a burst) and optionally
 * limit_conn (simultaneous connections), per client (IPv4 address or IPv6 /64) and proxy
 * host, with exempt networks and a dry run that only counts what would be refused.
 *
 * The zones go into /data/sentinel/nginx/rate-limits.conf (http level, included by
 * conf.d/sentinel.conf) and each limited host gets /data/sentinel/hosts/<id>.conf
 * (included by backend/templates/_sentinel.conf), so changing a policy never rewrites
 * host configs. Requests a security rule allowed ($corvus_skip) are not limited.
 *
 * Ported from Corvus (control/internal/compiler templates), Apache-2.0.
 */

import { normalizeCidrs } from "./ip.js";
import { ValidationErrors } from "./validate.js";

export const STATUS_CODES = [429, 503, 403];
export const MAX_POLICIES = 50;
const NAME_RE = /^[A-Za-z0-9 _.-]{1,64}$/;

const int = (v, def) => (v === undefined || v === null || v === "" ? def : Number(v));

/**
 * Validates a rate limit policy.
 *
 * @param   {Object}   p           {name, requests_per_second, burst, max_connections, status_code, dry_run, exempt, host_ids, enabled}
 * @param   {Function} [hostExists] id → whether the proxy host exists
 * @throws  {ValidationErrors}
 */
export const policy = (p, hostExists) => {
	const errs = new ValidationErrors();
	const out = {
		name: String(p?.name ?? "").trim(),
		enabled: p?.enabled !== false,
		requests_per_second: int(p?.requests_per_second, 10),
		burst: int(p?.burst, 20),
		max_connections: int(p?.max_connections, 0),
		status_code: int(p?.status_code, 429),
		dry_run: p?.dry_run === true,
		exempt: [],
		host_ids: [],
	};
	if (!NAME_RE.test(out.name)) {
		errs.add("name", "name must be 1-64 characters (letters, digits, space, _ . -)");
	}
	const range = (k, min, max) => {
		if (!Number.isInteger(out[k]) || out[k] < min || out[k] > max) errs.add(k, `must be between ${min} and ${max}`);
	};
	range("requests_per_second", 1, 100000);
	range("burst", 0, 100000);
	range("max_connections", 0, 100000);
	if (!STATUS_CODES.includes(out.status_code)) {
		errs.add("status_code", "status code must be 429, 503 or 403");
	}
	try {
		out.exempt = normalizeCidrs(Array.isArray(p?.exempt) ? p.exempt : []);
		if (out.exempt.length > 1000) errs.add("exempt", "at most 1000 exempt networks");
	} catch (err) {
		errs.add("exempt", err.message);
	}
	const ids = [...new Set((Array.isArray(p?.host_ids) ? p.host_ids : []).map(Number))];
	for (const h of ids) {
		if (!Number.isInteger(h) || h < 1 || (hostExists && !hostExists(h))) {
			errs.add("host_ids", `proxy host ${h} does not exist`);
		}
	}
	out.host_ids = ids;
	errs.throwIfAny();
	return out;
};

/**
 * Hosts that are in more than one enabled policy (a host can have one rate limit).
 *
 * @param   {Object[]} policies
 * @returns {number[]}
 */
export const conflicts = (policies) => {
	const seen = new Map();
	const out = new Set();
	for (const p of policies) {
		if (!p.enabled) continue;
		for (const h of p.host_ids || []) {
			if (seen.has(h)) out.add(h);
			seen.set(h, p.id);
		}
	}
	return [...out];
};

/**
 * nginx configuration of the enabled policies.
 *
 * @param   {Object[]} policies  validated policies with id
 * @param   {Set<number>} liveHosts  enabled proxy hosts
 * @returns {{http: string, hosts: Map<number, string>}}
 */
export const render = (policies, liveHosts) => {
	const http = ["# Sentinel rate limit policies, written by Nginx Proxy Manager. Do not edit.", ""];
	const hosts = new Map();
	for (const p of policies) {
		if (!p.enabled) continue;
		const id = Number(p.id);
		http.push(
			`# Policy #${id} "${p.name}": ${p.requests_per_second} r/s, burst ${p.burst}${p.dry_run ? " (dry run)" : ""}`,
			`geo $corvus_rl${id}_exempt {`,
			"\tdefault 0;",
			...p.exempt.map((c) => `\t${c} 1;`),
			"}",
			// counted per client and host: a policy shared by several hosts gives each its own budget
			`map "$corvus_rl${id}_exempt$corvus_skip" $corvus_rl${id}_key {`,
			'\t"0" "$corvus_key $corvus_client";',
			'\tdefault "";',
			"}",
			`limit_req_zone $corvus_rl${id}_key zone=corvus_rl${id}:10m rate=${p.requests_per_second}r/s;`,
		);
		if (p.max_connections > 0) {
			http.push(`limit_conn_zone $corvus_rl${id}_key zone=corvus_cl${id}:10m;`);
		}
		http.push("");
		const lines = [`# Sentinel rate limit policy #${id}`];
		lines.push(`limit_req zone=corvus_rl${id}${p.burst > 0 ? ` burst=${p.burst} nodelay` : ""};`);
		lines.push(`limit_req_status ${p.status_code};`);
		if (p.dry_run) lines.push("limit_req_dry_run on;");
		if (p.max_connections > 0) {
			lines.push(`limit_conn corvus_cl${id} ${p.max_connections};`);
			lines.push(`limit_conn_status ${p.status_code};`);
			if (p.dry_run) lines.push("limit_conn_dry_run on;");
		}
		for (const h of p.host_ids) {
			if (liveHosts.has(Number(h)) && !hosts.has(Number(h))) {
				hosts.set(Number(h), `${lines.join("\n")}\n`);
			}
		}
	}
	return { http: `${http.join("\n")}\n`, hosts };
};
