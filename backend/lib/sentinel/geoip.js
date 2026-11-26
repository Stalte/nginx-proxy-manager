/**
 * IP → country database for "Country" conditions.
 *
 * Source: DB-IP "IP to Country Lite" (CC BY 4.0, monthly, no account needed). The CSV
 * (start,end,country) is converted into a compact sorted range file that the gateway's
 * Lua code binary-searches (loaded once in the nginx master, shared by workers):
 *
 *   "CVGEO1\0\0" | n4 uint32 | n6 uint32          (16-byte header, little endian)
 *   v4 starts  n4 × uint32 (little endian)
 *   v4 codes   n4 × 2 bytes ASCII ("XX" = unknown / gap)
 *   v6 starts  n6 × 16 bytes (network order)
 *   v6 codes   n6 × 2 bytes
 *
 * Lookup: the last range whose start ≤ address.
 *
 * Ported from Corvus (control/internal/geoip), Apache-2.0.
 */

import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import zlib from "node:zlib";
import { ProxyAgent } from "proxy-agent";
import { parseIPv4, parseIPv6 } from "./ip.js";

export const ATTRIBUTION = "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0";
const URL_PATTERN = "https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz";
const MAX_GZIP = 64 * 1024 * 1024;
const MAX_ROWS = 4000000;
export const REFRESH_AGE_MS = 32 * 24 * 3600 * 1000;
const MAGIC = Buffer.from("CVGEO1\0\0", "latin1");
const V6_MAX = (1n << 128n) - 1n;

/**
 * Parses DB-IP CSV text into ranges.
 */
export class CSVParser {
	constructor() {
		this.s4 = [];
		this.s6 = [];
		this.rows = 0;
	}

	line(raw) {
		const f = raw.replace(/"/g, "").split(",");
		if (f.length < 3) {
			return;
		}
		const a = f[0].trim();
		const b = f[1].trim();
		const code = f[2].trim().toUpperCase();
		const cc = /^[A-Z]{2}$/.test(code) && code !== "ZZ" ? code : "XX";
		if (++this.rows > MAX_ROWS) {
			throw new Error(`more than ${MAX_ROWS} ranges`);
		}
		const a4 = parseIPv4(a);
		const b4 = parseIPv4(b);
		if (a4 !== null && b4 !== null) {
			if (b4 >= a4) this.s4.push([a4, b4, cc]);
			return;
		}
		const a6 = parseIPv6(a);
		const b6 = parseIPv6(b);
		if (a6 !== null && b6 !== null && b6 >= a6) {
			this.s6.push([a6, b6, cc]);
		}
	}

	/**
	 * @returns {{v4: Array<[number, string]>, v6: Array<[bigint, string]>}}  range starts with their country
	 */
	build() {
		this.s4.sort((x, y) => x[0] - y[0]);
		this.s6.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
		const v4 = [];
		const add4 = (start, cc) => {
			if (v4.length && v4[v4.length - 1][1] === cc) return;
			v4.push([start, cc]);
		};
		add4(0, "XX");
		let next = 0; // first address not yet covered
		for (const [a, b, cc] of this.s4) {
			if (a > next) add4(next, "XX");
			if (b + 1 <= next) continue; // fully overlapped
			add4(Math.max(a, next), cc);
			next = b + 1;
		}
		if (next <= 0xffffffff) add4(next, "XX");

		const v6 = [];
		const add6 = (start, cc) => {
			if (v6.length && v6[v6.length - 1][1] === cc) return;
			v6.push([start, cc]);
		};
		add6(0n, "XX");
		let next6 = 0n;
		for (const [a, b, cc] of this.s6) {
			if (next6 > V6_MAX) break;
			if (b < next6) continue;
			if (a > next6) add6(next6, "XX");
			add6(a > next6 ? a : next6, cc);
			next6 = b + 1n;
		}
		if (next6 <= V6_MAX) add6(next6, "XX");
		return { v4, v6 };
	}
}

/**
 * @param   {{v4: Array, v6: Array}} db
 * @param   {string} ip
 * @returns {string}  country code, "XX" when unknown
 */
export const lookup = (db, ip) => {
	const x4 = parseIPv4(ip);
	const search = (arr, x) => {
		let lo = 0;
		let hi = arr.length - 1;
		while (lo < hi) {
			const mid = (lo + hi + 1) >> 1;
			if (arr[mid][0] <= x) lo = mid;
			else hi = mid - 1;
		}
		return arr[lo]?.[1] || "XX";
	};
	if (x4 !== null) return search(db.v4, x4);
	const x6 = parseIPv6(ip);
	return x6 === null ? "XX" : search(db.v6, x6);
};

/**
 * @param   {{v4: Array, v6: Array}} db
 * @returns {Buffer}
 */
export const encode = (db) => {
	const n4 = db.v4.length;
	const n6 = db.v6.length;
	const buf = Buffer.alloc(16 + n4 * 6 + n6 * 18);
	MAGIC.copy(buf, 0);
	buf.writeUInt32LE(n4, 8);
	buf.writeUInt32LE(n6, 12);
	let o = 16;
	for (const [start] of db.v4) {
		buf.writeUInt32LE(start, o);
		o += 4;
	}
	for (const [, cc] of db.v4) {
		buf.write(cc, o, 2, "latin1");
		o += 2;
	}
	for (const [start] of db.v6) {
		buf.writeBigUInt64BE(start >> 64n, o);
		buf.writeBigUInt64BE(start & ((1n << 64n) - 1n), o + 8);
		o += 16;
	}
	for (const [, cc] of db.v6) {
		buf.write(cc, o, 2, "latin1");
		o += 2;
	}
	return buf;
};

/**
 * Rejects truncated or nonsensical downloads before they replace a good database.
 *
 * @param {{v4: Array, v6: Array}} db
 */
export const sanity = (db) => {
	if (db.v4.length < 10000) {
		throw new Error(`only ${db.v4.length} IPv4 ranges, refusing a truncated database`);
	}
	const got = lookup(db, "8.8.8.8");
	if (got !== "US") {
		throw new Error(`sanity check failed (8.8.8.8 → ${got})`);
	}
};

const download = (url) =>
	new Promise((resolve, reject) => {
		const parser = new CSVParser();
		const req = https.get(url, { agent: new ProxyAgent(), timeout: 30000 }, (res) => {
			if (res.statusCode !== 200) {
				res.resume();
				reject(new Error(`${url}: HTTP ${res.statusCode}`));
				return;
			}
			let gz = 0;
			let buf = "";
			const gunzip = zlib.createGunzip();
			res.on("data", (c) => {
				gz += c.length;
				if (gz > MAX_GZIP) req.destroy(new Error("download too large"));
			});
			res.pipe(gunzip);
			gunzip.setEncoding("utf8");
			gunzip.on("data", (chunk) => {
				buf += chunk;
				let i = buf.indexOf("\n");
				try {
					while (i >= 0) {
						parser.line(buf.slice(0, i));
						buf = buf.slice(i + 1);
						i = buf.indexOf("\n");
					}
				} catch (err) {
					req.destroy(err);
				}
			});
			gunzip.on("end", () => {
				try {
					if (buf) parser.line(buf);
					resolve(parser.build());
				} catch (err) {
					reject(err);
				}
			});
			gunzip.on("error", reject);
		});
		const timer = setTimeout(() => req.destroy(new Error("the download timed out")), 5 * 60 * 1000);
		req.on("close", () => clearTimeout(timer));
		req.on("timeout", () => req.destroy(new Error("the connection timed out")));
		req.on("error", reject);
	});

/**
 * Downloads this month's database (or last month's, early in a month) and installs it.
 *
 * @param   {string} file  destination (country.bin)
 * @returns {Promise<{ranges: number, source: string}>}
 */
export const refresh = async (file) => {
	const now = new Date();
	const months = [now, new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1))].map(
		(d) => `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`,
	);
	let lastErr;
	for (const m of months) {
		const url = URL_PATTERN.replace("%s", m);
		try {
			const db = await download(url);
			sanity(db);
			fs.mkdirSync(path.dirname(file), { recursive: true });
			const tmp = `${file}.tmp`;
			fs.writeFileSync(tmp, encode(db));
			fs.renameSync(tmp, file);
			fs.writeFileSync(
				path.join(path.dirname(file), "country.json"),
				JSON.stringify({
					source: url,
					updated_on: new Date().toISOString(),
					ranges: db.v4.length + db.v6.length,
				}),
			);
			return { ranges: db.v4.length + db.v6.length, source: url };
		} catch (err) {
			lastErr = err;
		}
	}
	throw lastErr;
};

/**
 * @param   {string} file
 * @returns {{available: boolean, updated_on: string|null, ranges: number, source: string, attribution: string}}
 */
export const status = (file) => {
	let meta = {};
	try {
		meta = JSON.parse(fs.readFileSync(path.join(path.dirname(file), "country.json"), "utf8"));
	} catch {
		// not downloaded yet
	}
	return {
		available: fs.existsSync(file),
		updated_on: meta.updated_on || null,
		ranges: meta.ranges || 0,
		source: meta.source || "",
		attribution: ATTRIBUTION,
	};
};
