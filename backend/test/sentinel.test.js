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
import { compile } from "../lib/sentinel/compile.js";
import { parse as parseFeed } from "../lib/sentinel/feeds.js";
import { CSVParser, encode as encodeGeo, lookup as geoLookup } from "../lib/sentinel/geoip.js";
import { encodeNet, isPublicIP, normalizeCidrs, parseEntry, parseIPv6 } from "../lib/sentinel/ip.js";
import { Builder, checkFile, encode, fromEntries, writeFile } from "../lib/sentinel/ipset.js";
import { feedURL, list as validateList, securityRule } from "../lib/sentinel/validate.js";

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
		for (const a of ["10.0.0.1", "127.0.0.1", "192.168.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"]) {
			assert.equal(isPublicIP(a), false, a);
		}
	});
});

describe("ipset", () => {
	it("merges overlapping and adjacent ranges", () => {
		const s = fromEntries(["10.0.0.0/8", "10.1.0.0/16", "11.0.0.0/8", "1.2.3.4", "1.2.3.5", "2001:db8::/32", "2001:db9::/32"]);
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
		assert.throws(() => securityRule({ name: "x", action: "challenge", expression: { groups } }, listKind));
		assert.throws(() => securityRule({ name: "x", action: "block", status_code: 500, expression: { groups } }, listKind));
		assert.throws(() =>
			securityRule({ name: "x", action: "block", scope: "hosts", host_ids: [7], expression: { groups } }, listKind, () => false),
		);
	});
});

describe("list validation", () => {
	it("accepts lists and normalises entries", () => {
		assert.deepEqual(validateList({ name: "a", kind: "ip", items: ["1.2.3.4", "1.2.3.4/32"] }).items, ["1.2.3.4/32"]);
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
		assert.deepEqual(config.hosts["5"], { rules: [1, 2], cf: false, exploits: true, body: "off", body_max: 1048576 });
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
