/**
 * Sentinel: address parsing, range files, rule validation, rules.json compilation, feed
 * parsing and the country database format. The Lua side reads what these produce
 * (/etc/nginx/lua/corvus), so the formats are checked byte for byte.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { buildRequest, underAttackText } from "../lib/sentinel/alerts.js";
import * as autoban from "../lib/sentinel/autoban.js";
import { compile } from "../lib/sentinel/compile.js";
import { parse as parseFeed } from "../lib/sentinel/feeds.js";
import { CSVParser, encode as encodeGeo, lookup as geoLookup } from "../lib/sentinel/geoip.js";
import { encodeNet, isPublicIP, normalizeCidrs, parseIPv6 } from "../lib/sentinel/ip.js";
import { Builder, checkFile, encode, fromEntries, writeFile } from "../lib/sentinel/ipset.js";
import * as ratelimit from "../lib/sentinel/ratelimit.js";
import * as underAttackLogic from "../lib/sentinel/underattack.js";
import {
	feedURL,
	securityRule,
	alerts as validateAlerts,
	list as validateList,
	underAttack as validateUnderAttack,
} from "../lib/sentinel/validate.js";

const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-test-"));

describe("ip", () => {
	it("parses IPv6 spellings", () => {
		assert.equal(parseIPv6("::1"), 1n);
		assert.equal(parseIPv6("::"), 0n);
		assert.equal(parseIPv6("::ffff:1.2.3.4"), 0xffff01020304n);
		assert.equal(parseIPv6("1:2:3:4:5:6:7:8"), 0x00010002000300040005000600070008n);
		for (const bad of ["fe80::1%eth0", ":::", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", "g::1"]) {
			assert.equal(parseIPv6(bad), null, bad);
		}
	});

	it("normalises networks", () => {
		assert.deepEqual(normalizeCidrs(["1.2.3.4", "10.1.2.3/8", "2001:db8::5/32", "::ffff:9.9.9.9", "1.2.3.4/32"]), [
			"1.2.3.4/32",
			"10.0.0.0/8",
			"2001:db8::/32",
			"9.9.9.9/32",
		]);
		// a broad IPv4-mapped network never matches: left out
		assert.deepEqual(normalizeCidrs(["::ffff:0:0/96"]), []);
		assert.throws(() => normalizeCidrs(["1.2.3.256"]));
		assert.throws(() => normalizeCidrs(["1.2.3.4/33"]));
		assert.throws(() => normalizeCidrs(["10.0.0.0/8; allow all"]));
	});

	it("encodes networks for the Lua matcher", () => {
		assert.equal(encodeNet("10.0.0.0/8"), "0a000000/8");
		assert.equal(encodeNet("2001:db8::/32"), "20010db8000000000000000000000000/32");
	});

	it("tells public addresses from local ones", () => {
		for (const a of ["8.8.8.8", "2606:4700::1"]) assert.equal(isPublicIP(a), true, a);
		for (const a of [
			"10.0.0.1",
			"127.0.0.1",
			"192.168.1.1",
			"100.64.0.1",
			"::1",
			"fd00::1",
			"fe80::1",
			"::ffff:10.0.0.1",
		]) {
			assert.equal(isPublicIP(a), false, a);
		}
	});
});

describe("ipset", () => {
	it("merges overlapping and adjacent ranges", () => {
		const s = fromEntries([
			"10.0.0.0/8",
			"10.1.0.0/16",
			"11.0.0.0/8",
			"1.2.3.4",
			"1.2.3.5",
			"2001:db8::/32",
			"2001:db9::/32",
		]);
		assert.deepEqual(Array.from(s.v4), [0x01020304, 0x01020305, 0x0a000000, 0x0bffffff]);
		assert.equal(s.v6.length, 1);
		assert.equal(s.v6[0][0], 0x20010db8n << 96n);
		assert.equal(s.v6[0][1], (0x20010db9n << 96n) | ((1n << 96n) - 1n));
	});

	it("writes the file format the gateway maps", () => {
		const s = fromEntries(["1.2.3.0/24", "2001:db8::1"]);
		const data = encode(s);
		assert.equal(data.subarray(0, 8).toString("latin1"), "CVIPSET\0");
		assert.equal(data.readUInt32LE(8), 1);
		assert.equal(data.readBigUInt64LE(16), 1n);
		assert.equal(data.readBigUInt64LE(24), 1n);
		assert.equal(data.length, 64 + 8 + 32);
		const payloadSum = crypto.createHash("sha256").update(data.subarray(64)).digest();
		assert.ok(data.subarray(32, 64).equals(payloadSum));
		assert.equal(data.readUInt32LE(64), 0x01020300);
		assert.equal(data.readUInt32LE(68), 0x010203ff);
		assert.equal(data.readBigUInt64LE(72), 0x20010db800000000n);
		assert.equal(data.readBigUInt64LE(80), 1n);

		const dir = tmpDir();
		const info = writeFile(dir, s);
		assert.equal(info.hash, crypto.createHash("sha256").update(data).digest("hex"));
		assert.equal(checkFile(dir, info.hash), true);
		fs.appendFileSync(info.path, "x");
		assert.equal(checkFile(dir, info.hash), false);
	});

	it("counts invalid entries", () => {
		const b = new Builder();
		assert.equal(b.add("not an address"), false);
		assert.equal(b.add("1.2.3.4"), true);
		assert.equal(b.invalid, 1);
	});
});

describe("rule validation", () => {
	const kinds = { 1: "ip", 2: "user_agent" };
	const listKind = (id) => kinds[id] || "";

	it("normalises a valid rule", () => {
		const r = securityRule(
			{
				name: " Block ",
				action: "block",
				expression: {
					groups: [
						[
							{ field: "ip.src", operator: "in", value: ["10.1.2.3/8", "list:1"] },
							{ field: "ip.country", operator: "in", value: ["cn", "ru"] },
							{ field: "http.header", name: "X-Api-Key", operator: "exists" },
						],
					],
				},
			},
			listKind,
			() => true,
		);
		assert.equal(r.name, "Block");
		assert.equal(r.status_code, 403);
		assert.equal(r.scope, "all");
		assert.deepEqual(r.expression.groups[0][0].value, ["10.0.0.0/8", "list:1"]);
		assert.deepEqual(r.expression.groups[0][1].value, ["CN", "RU"]);
		assert.equal(r.expression.groups[0][2].name, "x-api-key");
	});

	const bad = [
		["unknown field", { field: "http.cookie", operator: "eq", value: ["a"] }],
		["set operator on a string field", { field: "http.path", operator: "in2", value: ["a"] }],
		["string operator on a set field", { field: "ip.src", operator: "eq", value: ["1.2.3.4"] }],
		["bad network", { field: "ip.src", operator: "in", value: ["1.2.3.999"] }],
		["missing list", { field: "ip.src", operator: "in", value: ["list:9"] }],
		["wrong list kind", { field: "ip.src", operator: "in", value: ["list:2"] }],
		["UA list without a reference", { field: "http.user_agent_list", operator: "in", value: ["curl"] }],
		["bad country", { field: "ip.country", operator: "in", value: ["USA"] }],
		["lookahead", { field: "http.path", operator: "matches", value: ["^(?=a)"] }],
		["invalid regex", { field: "http.path", operator: "matches", value: ["(a"] }],
		["two values for eq", { field: "http.path", operator: "eq", value: ["a", "b"] }],
		["multi-line value", { field: "http.path", operator: "contains", value: ["a\nb"] }],
		["bad header name", { field: "http.header", name: "a b", operator: "exists" }],
	];
	for (const [what, cond] of bad) {
		it(`rejects ${what}`, () => {
			assert.throws(() =>
				securityRule({ name: "x", action: "block", expression: { groups: [[cond]] } }, listKind, () => true),
			);
		});
	}

	it("rejects an unknown action, status and host", () => {
		const groups = [[{ field: "http.path", operator: "eq", value: ["/"] }]];
		assert.throws(() => securityRule({ name: "x", action: "redirect", expression: { groups } }, listKind));
		assert.throws(() =>
			securityRule({ name: "x", action: "block", status_code: 500, expression: { groups } }, listKind),
		);
		assert.throws(() =>
			securityRule(
				{ name: "x", action: "block", scope: "hosts", host_ids: [7], expression: { groups } },
				listKind,
				() => false,
			),
		);
	});
});

describe("list validation", () => {
	it("accepts lists and normalises entries", () => {
		assert.deepEqual(validateList({ name: "a", kind: "ip", items: ["1.2.3.4", "1.2.3.4/32"] }).items, [
			"1.2.3.4/32",
		]);
		assert.deepEqual(validateList({ name: "a", kind: "user_agent", items: ["Curl", "curl", "sqlmap"] }).items, [
			"Curl",
			"sqlmap",
		]);
		const feed = validateList({ name: "a", kind: "ip", source_url: "https://example.com/x.txt", items: ["junk"] });
		assert.deepEqual(feed.items, []);
	});

	it("rejects unsafe feed URLs", () => {
		for (const u of [
			"http://example.com/x",
			"https://user:pw@example.com/x",
			"https://127.0.0.1/x",
			"https://[::1]/x",
			"https://10.0.0.1/x",
			"https://localhost/x",
			"file:///etc/passwd",
		]) {
			assert.throws(() => feedURL(u), u);
		}
		feedURL("https://check.torproject.org/torbulkexitlist");
	});

	it("rejects short User-Agent entries", () => {
		assert.throws(() => validateList({ name: "a", kind: "user_agent", items: ["ab"] }));
	});
});

describe("compile", () => {
	it("builds rules.json for proxy and redirection hosts", () => {
		const dir = tmpDir();
		const paths = { lists: path.join(dir, "lists"), geo: path.join(dir, "none.bin"), blockPage: "" };
		const lists = [
			{ id: 1, kind: "ip", name: "ips", source_url: "", items: ["203.0.113.0/24"] },
			{ id: 2, kind: "user_agent", name: "bots", source_url: "", items: ["SQLMap", "nikto"] },
			{ id: 3, kind: "ip", name: "feed", source_url: "https://example.com/x", data_hash: "", items: [] },
		];
		const rules = [
			{
				id: 10,
				name: "global",
				enabled: true,
				action: "block",
				status_code: 444,
				scope: "all",
				host_ids: [],
				expression: {
					groups: [
						[{ field: "ip.src", operator: "in", value: ["192.0.2.1", "list:1", "list:3"] }],
						[{ field: "http.user_agent_list", operator: "in", value: ["list:2"] }],
					],
				},
			},
			{
				id: 11,
				name: "host 5 only",
				enabled: true,
				action: "log",
				scope: "hosts",
				host_ids: [5],
				expression: { groups: [[{ field: "ip.country", operator: "in", value: ["CN"] }]] },
			},
			{
				id: 12,
				name: "disabled",
				enabled: false,
				action: "block",
				scope: "all",
				host_ids: [],
				expression: { groups: [[{ field: "http.path", operator: "eq", value: ["/"] }]] },
			},
			{
				id: 13,
				name: "deleted host",
				enabled: true,
				action: "block",
				scope: "hosts",
				host_ids: [99],
				expression: { groups: [[{ field: "http.path", operator: "eq", value: ["/"] }]] },
			},
		];
		const { config, listHashes, usesCountry } = compile(
			{
				rules,
				lists,
				proxyHosts: [
					{ id: 5, enabled: true, block_exploits: true },
					{ id: 6, enabled: true, block_exploits: false },
					{ id: 7, enabled: false, block_exploits: false },
				],
				redirectionHosts: [{ id: 2, enabled: true, block_exploits: false }],
			},
			paths,
		);
		assert.equal(usesCountry, true);
		assert.equal(config.geo, "");
		assert.equal(config.rules.length, 2);
		const [g, h] = config.rules;
		assert.equal(g.status, 444);
		assert.deepEqual(g.groups[0][0].v, ["c0000201/32"]);
		assert.equal(g.groups[0][0].l.length, 2);
		for (const ref of g.groups[0][0].l) {
			assert.ok(listHashes.has(ref.h));
			assert.ok(checkFile(paths.lists, ref.h));
		}
		assert.deepEqual(g.groups[1][0].v.sort(), ["nikto", "sqlmap"]);
		assert.equal(h.action, "log");
		assert.deepEqual(config.hosts["5"], {
			rules: [1, 2],
			cf: false,
			exploits: true,
			body: "off",
			body_max: 1048576,
		});
		assert.deepEqual(config.hosts["6"].rules, [1]);
		assert.equal(config.hosts["7"], undefined);
		assert.deepEqual(config.hosts.r2.rules, [1]);
	});
});

describe("feeds", () => {
	it("parses IP feeds with comments and skips broad ranges", () => {
		const f = parseFeed(
			"ip",
			"﻿# comment\n1.2.3.4 # tor\n5.6.7.0/24\tsomething\n; another\nnot-an-ip\n0.0.0.0/0\n2001:db8::/32\n",
		);
		assert.equal(f.count, 3);
		assert.match(f.warning, /1 invalid lines/);
		assert.match(f.warning, /1 ranges broader/);
		assert.equal(f.set.v4.length / 2, 2);
	});

	it("parses User-Agent feeds", () => {
		const f = parseFeed("user_agent", "# bad bots\nsqlmap\nNikto\nnikto\nab\nMass\\ Scanner\n");
		assert.deepEqual(f.items, ["sqlmap", "Nikto", "Mass Scanner"]);
		assert.match(f.warning, /1 invalid/);
	});

	it("refuses an empty feed", () => {
		assert.throws(() => parseFeed("ip", "# nothing\n"), /empty/);
		assert.throws(() => parseFeed("ip", "junk\n"), /no valid entries/);
	});
});

describe("geoip", () => {
	it("fills gaps, encodes and looks up", () => {
		const p = new CSVParser();
		for (const l of [
			"1.0.0.0,1.0.0.255,AU",
			"8.8.8.0,8.8.8.255,US",
			"8.8.9.0,8.8.9.255,US",
			"2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE",
			"bad,line,XX",
		]) {
			p.line(l);
		}
		const db = p.build();
		assert.equal(geoLookup(db, "1.0.0.7"), "AU");
		assert.equal(geoLookup(db, "8.8.9.9"), "US");
		assert.equal(geoLookup(db, "9.9.9.9"), "XX");
		assert.equal(geoLookup(db, "2001:db8::1"), "DE");
		assert.equal(geoLookup(db, "2001:db9::1"), "XX");
		const buf = encodeGeo(db);
		assert.equal(buf.subarray(0, 8).toString("latin1"), "CVGEO1\0\0");
		const n4 = buf.readUInt32LE(8);
		const n6 = buf.readUInt32LE(12);
		assert.equal(buf.length, 16 + n4 * 6 + n6 * 18);
		// 8.8.8.0-8.8.9.255 merged into one US range
		assert.equal(db.v4.filter(([, cc]) => cc === "US").length, 1);
	});
});

describe("browser challenge and under attack mode", () => {
	const groups = [[{ field: "http.path", operator: "eq", value: ["/"] }]];

	it("normalises challenge rules and rejects bad settings", () => {
		const r = securityRule({ name: "c", action: "challenge", expression: { groups } }, () => "");
		assert.deepEqual(r.challenge, { mode: "js", difficulty: 16, ttl: 86400, bind: "ip", pages: false });
		const c = securityRule(
			{ name: "c", action: "challenge", challenge: { mode: "cookie", ttl: 600 }, expression: { groups } },
			() => "",
		);
		assert.equal(c.challenge.mode, "cookie");
		assert.equal(c.challenge.ttl, 600);
		assert.equal(securityRule({ name: "b", action: "block", expression: { groups } }, () => "").challenge, null);
		for (const bad of [{ difficulty: 30 }, { difficulty: 11 }, { ttl: 60 }, { mode: "captcha" }, { bind: "x" }]) {
			assert.throws(() =>
				securityRule({ name: "c", action: "challenge", challenge: bad, expression: { groups } }, () => ""),
			);
		}
	});

	it("validates under attack settings with defaults", () => {
		const d = validateUnderAttack({});
		assert.equal(d.under_attack, "off");
		assert.deepEqual(d.config, {
			mode: "js",
			difficulty: 16,
			ttl: 3600,
			bind: "ip",
			pages: false,
			rps: 200,
			blocked_pct: 50,
			window_s: 30,
			duration_s: 900,
		});
		assert.equal(validateUnderAttack({ under_attack: "auto", config: { blocked_pct: 0 } }).config.blocked_pct, 0);
		for (const bad of [
			{ under_attack: "maybe" },
			{ config: { rps: 0 } },
			{ config: { window_s: 5 } },
			{ config: { duration_s: 10 } },
			{ config: { blocked_pct: 101 } },
		]) {
			assert.throws(() => validateUnderAttack(bad));
		}
	});

	it("compiles challenge rules and host under attack settings", () => {
		const { config } = compile(
			{
				rules: [
					{
						id: 3,
						enabled: true,
						name: "c",
						action: "challenge",
						challenge: { mode: "js", difficulty: 18 },
						scope: "all",
						host_ids: [],
						expression: { groups },
					},
				],
				lists: [],
				proxyHosts: [
					{ id: 1, enabled: true },
					{ id: 2, enabled: true },
					{ id: 4, enabled: true },
				],
				redirectionHosts: [],
				hostSettings: [
					{ proxy_host_id: 1, under_attack: "on", config: { mode: "cookie" } },
					{ proxy_host_id: 2, under_attack: "auto", config: {} },
					{ proxy_host_id: 4, under_attack: "off", config: {} },
				],
			},
			{ dir: tmpDir(), lists: tmpDir(), geo: "/nonexistent" },
		);
		assert.deepEqual(config.rules[0].challenge, {
			mode: "js",
			difficulty: 18,
			ttl: 86400,
			bind: "ip",
			pages: false,
		});
		assert.deepEqual(config.hosts["1"].under_attack, {
			on: true,
			mode: "cookie",
			difficulty: 16,
			ttl: 3600,
			bind: "ip",
			pages: false,
		});
		assert.equal(config.hosts["2"].under_attack.on, false);
		assert.equal(config.hosts["4"].under_attack, undefined);
	});

	it("activates on high traffic and ends after a quiet period", () => {
		const cfg = validateUnderAttack({ under_attack: "auto", config: { rps: 10, duration_s: 60 } }).config;
		const hosts = [{ id: 5, host: "a.example", config: cfg }];
		const st = underAttackLogic.emptyState();
		let t = { r: 100, b: 0, secs: 30 };
		const traffic = () => t;

		// 3.3 requests/s: below the threshold
		assert.deepEqual(underAttackLogic.evaluate(st, hosts, traffic, 0).transitions, []);
		t = { r: 600, b: 0, secs: 30 };
		const on = underAttackLogic.evaluate(st, hosts, traffic, 1000).transitions;
		assert.equal(on.length, 1);
		assert.equal(on[0].on, true);
		assert.match(on[0].reason, /20 requests\/s/);
		assert.deepEqual(underAttackLogic.payload(st, 2000).hosts, { 5: 61 });
		// still hot: extended
		underAttackLogic.evaluate(st, hosts, traffic, 30000);
		assert.equal(st.active["5"].until, 90000);
		// quiet, but within the period: stays on
		t = { r: 10, b: 0, secs: 30 };
		assert.deepEqual(underAttackLogic.evaluate(st, hosts, traffic, 60000).transitions, []);
		const off = underAttackLogic.evaluate(st, hosts, traffic, 90000).transitions;
		assert.equal(off.length, 1);
		assert.equal(off[0].on, false);
		assert.deepEqual(underAttackLogic.payload(st, 90000).hosts, {});
		assert.deepEqual(underAttackLogic.payload(st, 0).exempt, [
			"7f000000/8",
			"00000000000000000000000000000001/128",
		]);
	});

	it("uses the blocked share only with enough requests, and holds after a manual stop", () => {
		const cfg = validateUnderAttack({ config: { rps: 1000, blocked_pct: 50, duration_s: 60 } }).config;
		assert.deepEqual(underAttackLogic.over({ r: 40, b: 40, secs: 30 }, cfg), [false, ""]);
		assert.equal(underAttackLogic.over({ r: 100, b: 60, secs: 30 }, cfg)[0], true);
		assert.equal(underAttackLogic.over({ r: 100, b: 60, secs: 30 }, { ...cfg, blocked_pct: 0 })[0], false);

		const hosts = [{ id: 5, host: "a.example", config: cfg }];
		const st = underAttackLogic.emptyState();
		const hot = () => ({ r: 100, b: 60, secs: 30 });
		underAttackLogic.evaluate(st, hosts, hot, 0);
		const t = underAttackLogic.deactivate(st, 5, 60, 1000);
		assert.equal(t.manual, true);
		assert.equal(underAttackLogic.deactivate(st, 5, 60, 1000), null);
		// held for one period
		assert.deepEqual(underAttackLogic.evaluate(st, hosts, hot, 30000).transitions, []);
		assert.equal(underAttackLogic.evaluate(st, hosts, hot, 61000).transitions.length, 1);
		// host gone: activation ends silently
		assert.deepEqual(underAttackLogic.evaluate(st, [], hot, 62000), { changed: true, transitions: [] });
		assert.deepEqual(st.active, {});
		assert.deepEqual(underAttackLogic.parseState("{bad"), { active: {}, hold: {} });
	});

	it("formats alerts for each service", () => {
		const msg = { ...underAttackText({ host: "a.example", on: true, reason: "x", until: 0 }), event: "e" };
		assert.match(msg.title, /ON: a\.example/);
		assert.deepEqual(
			JSON.parse(buildRequest({ type: "discord", url: "https://d" }, msg).init.body).content.split("\n")[0],
			`**${msg.title}**`,
		);
		assert.ok(JSON.parse(buildRequest({ type: "slack", url: "https://s" }, msg).init.body).text);
		const ntfy = buildRequest({ type: "ntfy", url: "https://n/topic", token: "tk" }, msg).init;
		assert.equal(ntfy.body, msg.text);
		assert.equal(ntfy.headers.Authorization, "Bearer tk");
		assert.equal(
			buildRequest({ type: "gotify", url: "https://g/message", token: "k" }, msg).init.headers["X-Gotify-Key"],
			"k",
		);
		const hook = JSON.parse(buildRequest({ type: "webhook", url: "https://w" }, msg).init.body);
		assert.equal(hook.event, "e");

		assert.equal(validateAlerts({}).enabled, false);
		assert.throws(() => validateAlerts({ enabled: true, url: "" }));
		assert.throws(() => validateAlerts({ url: "ftp://x" }));
		assert.throws(() => validateAlerts({ type: "pager" }));
		assert.equal(validateAlerts({ enabled: true, type: "ntfy", url: "http://10.0.0.2/alerts" }).type, "ntfy");
	});
});

describe("automatic bans", () => {
	it("bans an IPv4 address or an IPv6 /64", () => {
		assert.equal(autoban.banKey(" 203.0.113.7 "), "203.0.113.7");
		assert.equal(autoban.banKey("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
		assert.equal(autoban.banKey("2001:db8:1:2::/64"), "2001:db8:1:2::/64");
		assert.equal(autoban.banKey("2001:db8::/48"), "");
		assert.equal(autoban.banKey("example.com"), "");
		assert.equal(autoban.banKey(""), "");
		// the gateway keys an IPv6 client by its first four groups in full
		assert.equal(autoban.gatewayKey("2001:db8:1:2::/64"), "2001:0db8:0001:0002");
		assert.equal(autoban.gatewayKey("203.0.113.7"), "203.0.113.7");
		assert.equal(autoban.hitKey("2001:0db8:0001:0002"), "2001:db8:1:2::/64");
		assert.equal(autoban.hitKey("198.51.100.1"), "198.51.100.1");
		assert.equal(autoban.hitKey("junk"), "");
	});

	it("never bans loopback or exempt networks", () => {
		assert.equal(autoban.exemptKey("127.0.0.1", []), true);
		assert.equal(autoban.exemptKey("::/64", []), true);
		assert.equal(autoban.exemptKey("192.168.1.5", ["192.168.0.0/16"]), true);
		assert.equal(autoban.exemptKey("2001:db8:1:2::/64", ["2001:db8:1:2::5/128"]), true);
		assert.equal(autoban.exemptKey("203.0.113.7", ["192.168.0.0/16"]), false);
		assert.equal(autoban.exemptKey("", []), true);
	});

	it("doubles the ban for each repeat offense", () => {
		const set = autoban.settings({ duration_s: 900, max_duration_s: 3600 });
		assert.equal(autoban.banUntil(set, 1, 0), 900 * 1000);
		assert.equal(autoban.banUntil(set, 2, 0), 1800 * 1000);
		assert.equal(autoban.banUntil(set, 3, 0), 3600 * 1000);
		assert.equal(autoban.banUntil(set, 9, 0), 3600 * 1000);
		const perm = autoban.settings({ permanent_after: 3 });
		assert.notEqual(autoban.banUntil(perm, 2, 0), null);
		assert.equal(autoban.banUntil(perm, 3, 0), null);
	});

	it("validates the settings", () => {
		const def = autoban.settings({});
		assert.equal(def.enabled, false);
		assert.deepEqual(def.bad_behaviour_codes, autoban.DEFAULT_CODES);
		assert.deepEqual(autoban.settings({ bad_behaviour_codes: [404, 403, 404] }).bad_behaviour_codes, [403, 404]);
		assert.deepEqual(autoban.settings({ exempt: ["10.1.2.3/8"] }).exempt, ["10.0.0.0/8"]);
		assert.throws(() => autoban.settings({ threshold: 1 }));
		assert.throws(() => autoban.settings({ bad_behaviour_codes: [200] }));
		assert.throws(() => autoban.settings({ bad_behaviour_codes: [] }));
		assert.equal(autoban.settings({ bad_behaviour: false, bad_behaviour_codes: [] }).bad_behaviour, false);
		assert.throws(() => autoban.settings({ duration_s: 3600, max_duration_s: 60 }));
		assert.throws(() => autoban.settings({ permanent_after: 1 }));
		assert.throws(() => autoban.settings({ exempt: ["not-a-network"] }));
	});

	it("builds the gateway settings", () => {
		assert.deepEqual(autoban.gatewayConfig(autoban.settings({})), { enabled: false });
		const cfg = autoban.gatewayConfig(autoban.settings({ enabled: true, exempt: ["10.0.0.0/8"] }));
		assert.equal(cfg.enabled, true);
		assert.deepEqual(cfg.codes, autoban.DEFAULT_CODES);
		assert.deepEqual(cfg.det, { threshold: 20, window: 600 });
		assert.deepEqual(cfg.exempt, ["127.0.0.0/8", "::1/128", "10.0.0.0/8"].map(encodeNet));
		// detections only: the error-response detector is off
		const det = autoban.gatewayConfig(autoban.settings({ enabled: true, bad_behaviour: false }));
		assert.deepEqual(det.codes, []);
		assert.ok(det.det);
		const bb = autoban.gatewayConfig(autoban.settings({ enabled: true, detections: false }));
		assert.equal(bb.det, undefined);
		assert.deepEqual(
			autoban.gatewayConfig(autoban.settings({ enabled: true, detections: false, bad_behaviour: false })),
			{ enabled: false },
		);
	});

	it("describes why a client was banned", () => {
		assert.equal(
			autoban.hitReason({ host: "a.example", window: 60, counts: { 404: 12, 403: 3, 401: 0 } }),
			"12×404, 3×403 on a.example in 60 s",
		);
		assert.equal(
			autoban.hitReason({ kind: "detections", host: "a.example", window: 600, counts: { blocked: 20 } }),
			"20 requests refused by Sentinel on a.example in 600 s",
		);
	});
});

describe("rate limits", () => {
	it("validates a policy", () => {
		const p = ratelimit.policy({ name: "Login", host_ids: [2, 2, 3] }, (h) => h !== 9);
		assert.equal(p.requests_per_second, 10);
		assert.equal(p.burst, 20);
		assert.equal(p.status_code, 429);
		assert.equal(p.enabled, true);
		assert.equal(p.dry_run, false);
		assert.deepEqual(p.host_ids, [2, 3]);
		assert.throws(() => ratelimit.policy({ name: "x", host_ids: [9] }, (h) => h !== 9));
		assert.throws(() => ratelimit.policy({ name: "" }));
		assert.throws(() => ratelimit.policy({ name: "a;b" }));
		assert.throws(() => ratelimit.policy({ name: "x", requests_per_second: 0 }));
		assert.throws(() => ratelimit.policy({ name: "x", status_code: 500 }));
		assert.throws(() => ratelimit.policy({ name: "x", exempt: ["}; evil"] }));
	});

	it("finds hosts in more than one enabled policy", () => {
		assert.deepEqual(
			ratelimit.conflicts([
				{ id: 1, enabled: true, host_ids: [1, 2] },
				{ id: 2, enabled: true, host_ids: [2, 3] },
				{ id: 3, enabled: false, host_ids: [3] },
			]),
			[2],
		);
	});

	it("renders the zones and the host includes", () => {
		const out = ratelimit.render(
			[
				{
					id: 4,
					name: "Seerr",
					enabled: true,
					requests_per_second: 5,
					burst: 10,
					max_connections: 20,
					status_code: 429,
					dry_run: true,
					exempt: ["10.0.0.0/8"],
					host_ids: [1, 2],
				},
				{ id: 5, name: "Off", enabled: false, requests_per_second: 1, burst: 0, exempt: [], host_ids: [3] },
			],
			new Set([1, 3]),
		);
		assert.match(out.http, /geo \$corvus_rl4_exempt \{\n\tdefault 0;\n\t10\.0\.0\.0\/8 1;\n\}/);
		assert.match(out.http, /limit_req_zone \$corvus_rl4_key zone=corvus_rl4:10m rate=5r\/s;/);
		assert.match(out.http, /limit_conn_zone \$corvus_rl4_key zone=corvus_cl4:10m;/);
		assert.doesNotMatch(out.http, /corvus_rl5/);
		// only enabled hosts get an include
		assert.deepEqual([...out.hosts.keys()], [1]);
		const host = out.hosts.get(1);
		assert.match(host, /limit_req zone=corvus_rl4 burst=10 nodelay;/);
		assert.match(host, /limit_req_dry_run on;/);
		assert.match(host, /limit_conn corvus_cl4 20;/);
		assert.match(host, /limit_conn_dry_run on;/);
	});
});
