/**
 * Downloads and parses list feeds: one entry per line, fetched over https.
 *
 * IP feeds may hold millions of entries: they are merged into address ranges while
 * they download (ipset.js), so memory grows with the number of entries, not with the
 * size of the download.
 *
 * Without a configured proxy, connections only go to public addresses: the target is
 * checked after DNS resolution, at connect time, so a feed URL can't be used to reach
 * services on the local network.
 *
 * Ported from Corvus (control/internal/feeds), Apache-2.0.
 */

import dns from "node:dns";
import https from "node:https";
import { ProxyAgent } from "proxy-agent";
import { isPublicIP, parseEntry } from "./ip.js";
import { Builder } from "./ipset.js";
import { feedURL, LIMITS, normalizeUAEntries, uaEntry } from "./validate.js";

export const MAX_IP_FEED_BYTES = 64 * 1024 * 1024;
export const MAX_UA_FEED_BYTES = 5 * 1024 * 1024;
const MAX_LINE = 4096;
const TIMEOUT_MS = 3 * 60 * 1000;
const MAX_REDIRECTS = 5;
// A remote list must not cover the whole address space (or a large share) with one entry
export const MIN_FEED_PREFIX_V4 = 8;
export const MIN_FEED_PREFIX_V6 = 16;

const hasProxy = () =>
	["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"].some((k) => process.env[k]);

// dns.lookup that refuses non-public addresses
const guardedLookup = (hostname, options, callback) => {
	dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
		if (err) {
			callback(err);
			return;
		}
		const ok = addrs.filter((a) => isPublicIP(a.address));
		if (!ok.length) {
			callback(new Error(`${hostname} does not resolve to a public address`));
			return;
		}
		if (options?.all) {
			callback(null, ok);
		} else {
			callback(null, ok[0].address, ok[0].family);
		}
	});
};

/**
 * Line parser for IP feeds.
 */
export class IPFeedParser {
	constructor(maxItems = LIMITS.maxIPFeedItems) {
		this.builder = new Builder();
		this.maxItems = maxItems;
		this.count = 0;
		this.skipped = 0;
		this.broad = 0;
		this.dropped = 0;
	}

	line(raw) {
		let line = raw;
		const c = line.search(/[#;]/);
		if (c >= 0) {
			line = line.slice(0, c);
		}
		const field = line.trim().split(/\s+/, 1)[0];
		if (!field) {
			return;
		}
		const n = parseEntry(field);
		if (n === null) {
			this.skipped++;
		} else if (n === false) {
			// IPv4-mapped network broader than /104: never matches
		} else if ((n.v === 4 && n.prefix < MIN_FEED_PREFIX_V4) || (n.v === 6 && n.prefix < MIN_FEED_PREFIX_V6)) {
			this.broad++;
		} else if (this.count >= this.maxItems) {
			this.dropped++;
		} else {
			this.builder.addNet(n);
			this.count++;
		}
	}

	finish() {
		if (this.count === 0) {
			throw emptyErr(this.skipped + this.broad);
		}
		const warn = [];
		if (this.skipped) warn.push(`${this.skipped} invalid lines ignored`);
		if (this.broad) {
			warn.push(
				`${this.broad} ranges broader than /${MIN_FEED_PREFIX_V4} (IPv4) or /${MIN_FEED_PREFIX_V6} (IPv6) ignored`,
			);
		}
		if (this.dropped) warn.push(`${this.count + this.dropped} entries, only the first ${this.maxItems} are used`);
		return { set: this.builder.build(), count: this.count, warning: warn.join("; ") };
	}
}

/**
 * Line parser for User-Agent feeds.
 */
export class UAFeedParser {
	constructor() {
		this.raw = [];
		this.skipped = 0;
	}

	line(raw) {
		let line = raw.trim();
		if (line === "" || line[0] === "#" || line[0] === ";") {
			return;
		}
		if (line.includes("\\")) {
			line = line.replace(/\\(.)/g, "$1").trim();
		}
		try {
			uaEntry(line);
			this.raw.push(line);
		} catch {
			this.skipped++;
		}
	}

	finish() {
		let items = normalizeUAEntries(this.raw);
		if (!items.length) {
			throw emptyErr(this.skipped);
		}
		const warn = [];
		if (this.skipped) warn.push(`${this.skipped} invalid lines ignored`);
		if (items.length > LIMITS.maxUAListItems) {
			warn.push(`${items.length} entries, only the first ${LIMITS.maxUAListItems} are used`);
			items = items.slice(0, LIMITS.maxUAListItems);
		}
		return { items, count: items.length, warning: warn.join("; ") };
	}
}

const emptyErr = (skipped) =>
	new Error(skipped ? `no valid entries (${skipped} lines not understood)` : "the feed is empty");

/**
 * Feeds text to a parser line by line.
 *
 * @param {IPFeedParser|UAFeedParser} parser
 * @returns {{write: (chunk: string) => void, end: () => void}}
 */
export const lineSplitter = (parser) => {
	let buf = "";
	let first = true;
	let skipping = false;
	return {
		write(chunk) {
			let s = chunk;
			if (first) {
				s = s.replace(/^﻿/, "");
				first = false;
			}
			buf += s;
			let i = buf.indexOf("\n");
			while (i >= 0) {
				const line = buf.slice(0, i);
				buf = buf.slice(i + 1);
				if (skipping) {
					skipping = false;
				} else if (line.length > MAX_LINE) {
					parser.skipped++;
				} else {
					parser.line(line);
				}
				i = buf.indexOf("\n");
			}
			if (buf.length > MAX_LINE) {
				// too long for a list entry: skip the rest of the line
				if (!skipping) parser.skipped++;
				skipping = true;
				buf = "";
			}
		},
		end() {
			if (!skipping && buf !== "") {
				parser.line(buf);
			}
			buf = "";
		},
	};
};

/**
 * Parses a whole feed body (tests, small feeds).
 *
 * @param   {string} kind  ip | user_agent
 * @param   {string} text
 * @returns {Object}       {set, count, warning} for IP feeds, {items, count, warning} for User-Agent feeds
 */
export const parse = (kind, text) => {
	const parser = kind === "user_agent" ? new UAFeedParser() : new IPFeedParser();
	const s = lineSplitter(parser);
	s.write(text);
	s.end();
	return parser.finish();
};

/**
 * Downloads and parses a feed.
 *
 * @param   {string} url
 * @param   {string} kind  ip | user_agent
 * @returns {Promise<Object>}  as parse()
 */
export const fetchFeed = (url, kind) => {
	const maxBytes = kind === "user_agent" ? MAX_UA_FEED_BYTES : MAX_IP_FEED_BYTES;
	const useProxy = hasProxy();
	const agent = useProxy ? new ProxyAgent() : undefined;

	const get = (target, redirects) =>
		new Promise((resolve, reject) => {
			try {
				feedURL(target);
			} catch (err) {
				reject(err);
				return;
			}
			const parser = kind === "user_agent" ? new UAFeedParser() : new IPFeedParser();
			const splitter = lineSplitter(parser);
			const opts = {
				headers: { "User-Agent": "nginx-proxy-manager-sentinel", Accept: "text/plain, */*" },
				timeout: 30000, // idle socket
			};
			if (agent) {
				opts.agent = agent;
			} else {
				opts.lookup = guardedLookup;
			}
			const req = https.get(target, opts, (res) => {
				if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
					res.resume();
					if (redirects >= MAX_REDIRECTS) {
						reject(new Error("too many redirects"));
						return;
					}
					let next;
					try {
						next = new URL(res.headers.location, target).toString();
					} catch {
						reject(new Error("invalid redirect"));
						return;
					}
					resolve(get(next, redirects + 1));
					return;
				}
				if (res.statusCode !== 200) {
					res.resume();
					reject(new Error(`the server answered HTTP ${res.statusCode}`));
					return;
				}
				let bytes = 0;
				res.setEncoding("utf8");
				res.on("data", (chunk) => {
					bytes += Buffer.byteLength(chunk);
					if (bytes > maxBytes) {
						req.destroy(new Error(`the feed is larger than ${Math.round(maxBytes / 1048576)} MB`));
						return;
					}
					splitter.write(chunk);
				});
				res.on("end", () => {
					try {
						splitter.end();
						resolve(parser.finish());
					} catch (err) {
						reject(err);
					}
				});
				res.on("error", reject);
			});
			const timer = setTimeout(() => req.destroy(new Error("the download timed out")), TIMEOUT_MS);
			req.on("close", () => clearTimeout(timer));
			req.on("timeout", () => req.destroy(new Error("the connection timed out")));
			req.on("error", reject);
		});

	return get(url, 0);
};
