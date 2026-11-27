/**
 * Builds rules.json, the configuration the gateway's Lua code reads at every nginx
 * (re)load (/etc/nginx/lua/corvus/rules.lua).
 *
 * Ported from Corvus (control/internal/compiler/rules.go), Apache-2.0.
 */

import fs from "node:fs";
import { sentinel as logger } from "../../logger.js";
import { encodeNet } from "./ip.js";
import { checkFile, fromEntries, writeFile } from "./ipset.js";
import { listRef, securityRule, underAttack } from "./validate.js";

/**
 * "under_attack" of a host in rules.json, or null when the mode is off (or the stored
 * settings are invalid). "auto" hosts are challenged only while the backend has pushed
 * an activation to the gateway (see backend/internal/sentinel-underattack.js).
 */
const underAttackConfig = (row) => {
	if (!row || row.under_attack === "off") {
		return null;
	}
	try {
		const { under_attack: mode, config } = underAttack(row);
		if (mode === "off") return null;
		return {
			on: mode === "on",
			mode: config.mode,
			difficulty: config.difficulty,
			ttl: config.ttl,
			bind: config.bind,
			pages: config.pages,
		};
	} catch (err) {
		logger.error(`Sentinel under attack settings of proxy host #${row.proxy_host_id} are invalid: ${err.message}`);
		return null;
	}
};

export const PATHS = {
	dir: "/data/sentinel",
	rules: "/data/sentinel/rules.json",
	lists: "/data/sentinel/lists",
	geo: "/data/sentinel/geoip/country.bin",
	blockPage: "/etc/nginx/lua/pages/blocked.html",
	challengePage: "/etc/nginx/lua/pages/challenge.html",
	secrets: "/data/sentinel/secrets.json",
	underAttack: "/data/sentinel/under-attack.json",
};

/**
 * @param   {Object}   input
 * @param   {Object[]} input.rules             rule rows, in evaluation order
 * @param   {Object[]} input.lists             list rows
 * @param   {Object[]} input.proxyHosts        {id, enabled, block_exploits}
 * @param   {Object[]} input.redirectionHosts  {id, enabled, block_exploits}
 * @param   {Object[]} [input.hostSettings]    sentinel_host rows {proxy_host_id, under_attack, config}
 * @param   {Object}   [paths]
 * @returns {{config: Object, listHashes: Set<string>, usesCountry: boolean}}
 */
export const compile = ({ rules, lists, proxyHosts, redirectionHosts, hostSettings = [] }, paths = PATHS) => {
	const listById = new Map(lists.map((l) => [Number(l.id), l]));
	const listKind = (id) => listById.get(id)?.kind || "";
	const hostIds = new Set(proxyHosts.map((h) => Number(h.id)));
	const listHashes = new Set();
	const listRefs = new Map();
	let usesCountry = false;

	// range file of an IP list: the stored file of a feed, or one written from its entries
	const listFile = (id) => {
		if (listRefs.has(id)) {
			return listRefs.get(id);
		}
		const l = listById.get(id);
		let hash = "";
		if (l.source_url) {
			if (l.data_hash && checkFile(paths.lists, l.data_hash)) {
				hash = l.data_hash;
			} else {
				// not downloaded yet (or the file is gone): empty until the next refresh
				if (l.data_hash) {
					logger.warn(`Sentinel list "${l.name}" has no usable data file, it is empty until refreshed`);
				}
				hash = writeFile(paths.lists, fromEntries([])).hash;
			}
		} else {
			hash = writeFile(paths.lists, fromEntries(l.items || [])).hash;
		}
		listHashes.add(hash);
		const ref = { p: `${paths.lists}/${hash}.bin`, h: hash };
		listRefs.set(id, ref);
		return ref;
	};

	const config = {
		rules: [],
		hosts: {},
		geo: fs.existsSync(paths.geo) ? paths.geo : "",
	};
	if (paths.blockPage && fs.existsSync(paths.blockPage)) {
		config.block_page = paths.blockPage;
	}
	if (paths.challengePage && fs.existsSync(paths.challengePage)) {
		config.challenge_page = paths.challengePage;
	}
	if (paths.secrets && fs.existsSync(paths.secrets)) {
		config.secrets = paths.secrets;
	}
	const settingsByHost = new Map(hostSettings.map((s) => [Number(s.proxy_host_id), s]));

	const scopes = [];
	for (const row of rules) {
		if (!row.enabled) {
			continue;
		}
		let r = row;
		if (r.scope === "hosts") {
			// a rule whose hosts were all deleted applies nowhere: skip it
			const live = (r.host_ids || []).filter((h) => hostIds.has(Number(h)));
			if (!live.length) {
				continue;
			}
			r = { ...r, host_ids: live };
		}
		// never render a rule that would not pass validation
		try {
			r = { ...securityRule(r, listKind, (h) => hostIds.has(h)), id: row.id };
		} catch (err) {
			logger.error(`Sentinel rule #${row.id} "${row.name}" is invalid and was left out: ${err.message}`);
			continue;
		}
		const rj = { id: r.id, action: r.action, status: r.status_code, skip_auth: false, groups: [] };
		if (r.action === "challenge") {
			rj.challenge = r.challenge;
		}
		for (const g of r.expression.groups) {
			const cg = [];
			for (const c of g) {
				const cj = { f: c.field, op: c.operator, v: c.value };
				if (c.name) cj.n = c.name;
				if (c.ci) cj.ci = true;
				if (c.field === "ip.src") {
					const nets = [];
					const files = [];
					for (const v of c.value) {
						const id = listRef(v);
						if (id) {
							files.push(listFile(id));
						} else {
							nets.push(encodeNet(v));
						}
					}
					cj.v = nets;
					if (files.length) cj.l = files;
				}
				if (c.field === "http.user_agent_list") {
					const seen = new Set();
					for (const v of c.value) {
						for (const e of listById.get(listRef(v))?.items || []) {
							seen.add(String(e).toLowerCase());
						}
					}
					cj.v = [...seen];
				}
				if (c.field === "ip.country") {
					usesCountry = true;
				}
				cg.push(cj);
			}
			rj.groups.push(cg);
		}
		config.rules.push(rj);
		scopes.push({ all: r.scope === "all", hosts: new Set(r.host_ids.map(Number)) });
	}

	for (const h of proxyHosts) {
		if (!h.enabled) continue;
		const hj = { rules: [], cf: false, exploits: !!h.block_exploits, body: "off", body_max: 1048576 };
		scopes.forEach((sc, i) => {
			if (sc.all || sc.hosts.has(Number(h.id))) hj.rules.push(i + 1);
		});
		const hs = settingsByHost.get(Number(h.id));
		const ua = underAttackConfig(hs);
		if (ua) {
			hj.under_attack = ua;
		}
		if (hs?.no_autoban) {
			hj.no_autoban = true;
		}
		config.hosts[String(h.id)] = hj;
	}
	// redirection hosts get rules that apply to all hosts and exploit blocking
	for (const h of redirectionHosts) {
		if (!h.enabled) continue;
		const hj = { rules: [], cf: false, exploits: !!h.block_exploits, body: "off", body_max: 1048576 };
		scopes.forEach((sc, i) => {
			if (sc.all) hj.rules.push(i + 1);
		});
		config.hosts[`r${h.id}`] = hj;
	}
	return { config, listHashes, usesCountry };
};
