/**
 * IP lists as compact range files, mapped read-only by the gateway
 * (/etc/nginx/lua/corvus/iplist.lua), so a list of millions of entries costs its file size
 * once (shared page cache), not a Lua table per nginx worker.
 *
 * File format (version 1), all integers little-endian:
 *
 *   offset  size  field
 *   0       8     magic "CVIPSET\0"
 *   8       4     format version (1)
 *   12      4     reserved (0)
 *   16      8     n4: number of IPv4 ranges
 *   24      8     n6: number of IPv6 ranges
 *   32      32    SHA-256 of the payload (everything after the header)
 *   64      8·n4  IPv4 ranges: uint32 first, uint32 last
 *   …       32·n6 IPv6 ranges: uint64 first_hi, first_lo, last_hi, last_lo
 *
 * Ranges are inclusive, sorted, and neither overlap nor touch. The file is named after
 * the SHA-256 of its whole content (<sha256>.bin).
 *
 * Ported from Corvus (control/internal/ipset), Apache-2.0.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseEntry } from "./ip.js";

const MAGIC = Buffer.from("CVIPSET\0", "latin1");
const HEADER = 64;
const HASH_RE = /^[0-9a-f]{64}$/;
const MASK64 = (1n << 64n) - 1n;

/**
 * Collects networks and merges them into ranges.
 */
class Builder {
	constructor() {
		this.v4 = new BigUint64Array(1024);
		this.n4 = 0;
		this.v6 = [];
		this.networks = 0;
		this.invalid = 0;
	}

	/**
	 * @param   {string} entry  an address or CIDR network
	 * @returns {boolean}       whether it was valid
	 */
	add(entry) {
		const n = parseEntry(entry);
		if (n === null) {
			this.invalid++;
			return false;
		}
		if (n !== false) {
			this.addNet(n);
		}
		return true;
	}

	/**
	 * @param {Object} n  a network from parseEntry()
	 */
	addNet(n) {
		this.networks++;
		if (n.v === 4) {
			if (this.n4 === this.v4.length) {
				const bigger = new BigUint64Array(this.v4.length * 2);
				bigger.set(this.v4);
				this.v4 = bigger;
			}
			this.v4[this.n4++] = (BigInt(n.first) << 32n) | BigInt(n.last);
		} else {
			this.v6.push([n.first, n.last]);
		}
	}

	/**
	 * @returns {{v4: Uint32Array, v6: bigint[][], networks: number}}  merged ranges (v4: first, last pairs)
	 */
	build() {
		const sorted = this.v4.subarray(0, this.n4).sort();
		const out4 = new Uint32Array(this.n4 * 2);
		let k = 0;
		let curF = -1;
		let curL = -1;
		for (let i = 0; i < sorted.length; i++) {
			const f = Number(sorted[i] >> 32n);
			const l = Number(sorted[i] & 0xffffffffn);
			if (curF >= 0 && f <= curL + 1) {
				if (l > curL) curL = l;
				continue;
			}
			if (curF >= 0) {
				out4[k++] = curF;
				out4[k++] = curL;
			}
			curF = f;
			curL = l;
		}
		if (curF >= 0) {
			out4[k++] = curF;
			out4[k++] = curL;
		}
		this.v6.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
		const out6 = [];
		for (const [f, l] of this.v6) {
			const prev = out6[out6.length - 1];
			if (prev && f <= prev[1] + 1n) {
				if (l > prev[1]) prev[1] = l;
				continue;
			}
			out6.push([f, l]);
		}
		return { v4: out4.slice(0, k), v6: out6, networks: this.networks };
	}
}

/**
 * Encodes merged ranges as a range file.
 *
 * @param   {{v4: Uint32Array, v6: bigint[][]}} set
 * @returns {Buffer}
 */
const encode = (set) => {
	const n4 = set.v4.length / 2;
	const n6 = set.v6.length;
	const payload = Buffer.alloc(n4 * 8 + n6 * 32);
	for (let i = 0; i < set.v4.length; i++) {
		payload.writeUInt32LE(set.v4[i], i * 4);
	}
	let o = n4 * 8;
	for (const [f, l] of set.v6) {
		payload.writeBigUInt64LE(f >> 64n, o);
		payload.writeBigUInt64LE(f & MASK64, o + 8);
		payload.writeBigUInt64LE(l >> 64n, o + 16);
		payload.writeBigUInt64LE(l & MASK64, o + 24);
		o += 32;
	}
	const header = Buffer.alloc(HEADER);
	MAGIC.copy(header, 0);
	header.writeUInt32LE(1, 8);
	header.writeBigUInt64LE(BigInt(n4), 16);
	header.writeBigUInt64LE(BigInt(n6), 24);
	crypto.createHash("sha256").update(payload).digest().copy(header, 32);
	return Buffer.concat([header, payload]);
};

/**
 * Builds a set from list entries.
 *
 * @param   {string[]} entries
 * @returns {{v4: Uint32Array, v6: bigint[][], networks: number}}
 */
const fromEntries = (entries) => {
	const b = new Builder();
	for (const e of entries || []) {
		if (String(e).trim() !== "" && !b.add(e)) {
			throw new Error(`invalid IP address or network "${String(e).slice(0, 64)}"`);
		}
	}
	return b.build();
};

/**
 * Writes a range file into dir, named after its SHA-256.
 *
 * @param   {string} dir
 * @param   {{v4: Uint32Array, v6: bigint[][]}} set
 * @returns {{hash: string, path: string, ranges: number}}
 */
const writeFile = (dir, set) => {
	const data = encode(set);
	const hash = crypto.createHash("sha256").update(data).digest("hex");
	const file = path.join(dir, `${hash}.bin`);
	fs.mkdirSync(dir, { recursive: true });
	if (!fs.existsSync(file)) {
		const tmp = `${file}.${process.pid}.tmp`;
		fs.writeFileSync(tmp, data);
		fs.renameSync(tmp, file);
	} else {
		// in use again: keep it out of a cleanup
		const now = new Date();
		fs.utimesSync(file, now, now);
	}
	return { hash, path: file, ranges: set.v4.length / 2 + set.v6.length };
};

/**
 * Checks that a stored range file exists and matches its name.
 *
 * @param   {string} dir
 * @param   {string} hash
 * @returns {boolean}
 */
const checkFile = (dir, hash) => {
	if (!HASH_RE.test(hash || "")) {
		return false;
	}
	try {
		const data = fs.readFileSync(path.join(dir, `${hash}.bin`));
		if (data.length < HEADER || !data.subarray(0, 8).equals(MAGIC)) {
			return false;
		}
		return crypto.createHash("sha256").update(data).digest("hex") === hash;
	} catch {
		return false;
	}
};

/**
 * Removes range files not in keep and older than an hour (a file written for a
 * configuration that is still being tested must survive).
 *
 * @param {string}      dir
 * @param {Set<string>} keep  hashes in use
 */
const cleanup = (dir, keep) => {
	let names = [];
	try {
		names = fs.readdirSync(dir);
	} catch {
		return;
	}
	const cutoff = Date.now() - 3600 * 1000;
	for (const name of names) {
		const m = name.match(/^([0-9a-f]{64})\.bin$/);
		if (!m || keep.has(m[1])) {
			continue;
		}
		try {
			const file = path.join(dir, name);
			if (fs.statSync(file).mtimeMs < cutoff) {
				fs.unlinkSync(file);
			}
		} catch {
			// ignore
		}
	}
};

export { Builder, checkFile, cleanup, encode, fromEntries, HASH_RE, writeFile };
