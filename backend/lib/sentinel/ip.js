/**
 * IP address and network parsing for Sentinel.
 *
 * Networks are normalised the way the gateway matches them: a bare address is a /32 or
 * /128, host bits are cleared, and an IPv4-mapped IPv6 network (::ffff:a.b.c.d/p) of /104
 * or narrower is that IPv4 network. Broader mapped networks never match an address nginx
 * sees and are left out.
 *
 * Ported from Corvus (control/internal/ipset, control/internal/netcfg), Apache-2.0.
 */

const IPV4_RE = /^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$/;

/**
 * @param   {string} s
 * @returns {number|null}  the address as an unsigned 32-bit number
 */
const parseIPv4 = (s) => {
	if (!IPV4_RE.test(s)) {
		return null;
	}
	const p = s.split(".");
	return ((Number(p[0]) << 24) | (Number(p[1]) << 16) | (Number(p[2]) << 8) | Number(p[3])) >>> 0;
};

/**
 * @param   {string} s
 * @returns {bigint|null}  the address as an unsigned 128-bit number
 */
const parseIPv6 = (s) => {
	if (typeof s !== "string" || s.length < 2 || s.length > 45 || s.includes("%")) {
		return null;
	}
	let str = s;
	// embedded IPv4 in the last 32 bits: rewrite as two hex groups
	const lastColon = str.lastIndexOf(":");
	if (lastColon >= 0 && str.indexOf(".", lastColon) > lastColon) {
		const v4 = parseIPv4(str.slice(lastColon + 1));
		if (v4 === null) {
			return null;
		}
		str = `${str.slice(0, lastColon + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
	}
	const parts = str.split("::");
	if (parts.length > 2) {
		return null;
	}
	const parseGroups = (g) => {
		if (g === "") {
			return [];
		}
		const out = [];
		for (const x of g.split(":")) {
			if (!/^[0-9a-fA-F]{1,4}$/.test(x)) {
				return null;
			}
			out.push(Number.parseInt(x, 16));
		}
		return out;
	};
	const head = parseGroups(parts[0]);
	const rest = parts.length === 2 ? parseGroups(parts[1]) : [];
	if (head === null || rest === null) {
		return null;
	}
	let groups;
	const have = head.length + rest.length;
	if (parts.length === 2) {
		if (have > 7) {
			return null;
		}
		groups = [...head, ...new Array(8 - have).fill(0), ...rest];
	} else {
		if (have !== 8) {
			return null;
		}
		groups = head;
	}
	let v = 0n;
	for (const g of groups) {
		v = (v << 16n) | BigInt(g);
	}
	return v;
};

const V6_MAPPED_PREFIX = 0xffffn << 32n;
const V6_MAX = (1n << 128n) - 1n;

/**
 * Parses one entry: an address or a CIDR network.
 *
 * @param   {string} raw
 * @returns {{v: 4, first: number, last: number, prefix: number}|{v: 6, first: bigint, last: bigint, prefix: number}|null|false}
 *          the network, null when invalid, false when valid but never matching (broad mapped network)
 */
const parseEntry = (raw) => {
	const s = String(raw).trim();
	if (s === "") {
		return null;
	}
	let addr = s;
	let prefix = null;
	const slash = s.indexOf("/");
	if (slash >= 0) {
		addr = s.slice(0, slash);
		const p = s.slice(slash + 1);
		if (!/^[0-9]{1,3}$/.test(p)) {
			return null;
		}
		prefix = Number(p);
	}
	const v4 = parseIPv4(addr);
	if (v4 !== null) {
		if (prefix === null) {
			prefix = 32;
		}
		if (prefix > 32) {
			return null;
		}
		return v4Net(v4, prefix);
	}
	const v6 = parseIPv6(addr);
	if (v6 === null) {
		return null;
	}
	if (prefix === null) {
		prefix = 128;
	}
	if (prefix > 128) {
		return null;
	}
	if (v6 >> 32n === 0xffffn) {
		// IPv4-mapped
		if (prefix < 104) {
			return false;
		}
		return v4Net(Number(v6 & 0xffffffffn), prefix - 96);
	}
	const hostBits = BigInt(128 - prefix);
	const mask = hostBits === 128n ? 0n : (V6_MAX >> hostBits) << hostBits;
	const first = v6 & mask;
	return { v: 6, first, last: first | (V6_MAX ^ mask), prefix };
};

const v4Net = (addr, prefix) => {
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	const first = (addr & mask) >>> 0;
	return { v: 4, first, last: (first | (~mask >>> 0)) >>> 0, prefix };
};

const v4String = (x) => `${x >>> 24}.${(x >>> 16) & 255}.${(x >>> 8) & 255}.${x & 255}`;

const v6String = (x) => {
	const groups = [];
	for (let i = 7; i >= 0; i--) {
		groups.push(Number((x >> BigInt(i * 16)) & 0xffffn).toString(16));
	}
	// compress the longest run of zero groups
	let best = -1;
	let bestLen = 0;
	for (let i = 0; i < 8; ) {
		if (groups[i] !== "0") {
			i++;
			continue;
		}
		let j = i;
		while (j < 8 && groups[j] === "0") j++;
		if (j - i > bestLen && j - i > 1) {
			best = i;
			bestLen = j - i;
		}
		i = j;
	}
	if (best < 0) {
		return groups.join(":");
	}
	return `${groups.slice(0, best).join(":")}::${groups.slice(best + bestLen).join(":")}`;
};

/**
 * Normalises networks entered by hand: CIDR notation, host bits cleared, de-duplicated.
 *
 * @param   {string[]} values
 * @returns {string[]}
 * @throws  {Error} on an invalid entry
 */
const normalizeCidrs = (values) => {
	const out = [];
	const seen = new Set();
	for (const raw of values || []) {
		const s = String(raw).trim();
		if (s === "") {
			continue;
		}
		const n = parseEntry(s);
		if (n === null) {
			throw new Error(`invalid IP address or network "${s.slice(0, 64)}"`);
		}
		if (n === false) {
			continue;
		}
		const str = n.v === 4 ? `${v4String(n.first)}/${n.prefix}` : `${v6String(n.first)}/${n.prefix}`;
		if (!seen.has(str)) {
			seen.add(str);
			out.push(str);
		}
	}
	return out;
};

/**
 * Encodes a network for the Lua matcher: "<hex network bytes>/<prefix>".
 *
 * @param   {string} cidr  normalised
 * @returns {string}
 */
const encodeNet = (cidr) => {
	const n = parseEntry(cidr);
	if (!n) {
		throw new Error(`invalid network "${cidr}"`);
	}
	if (n.v === 4) {
		return `${n.first.toString(16).padStart(8, "0")}/${n.prefix}`;
	}
	return `${n.first.toString(16).padStart(32, "0")}/${n.prefix}`;
};

/**
 * Whether an address is globally routable (not loopback, private, link-local, CGNAT,
 * unspecified, multicast or documentation ranges).
 *
 * @param   {string} addr
 * @returns {boolean}
 */
const isPublicIP = (addr) => {
	const v4 = parseIPv4(addr);
	if (v4 !== null) {
		return !NON_PUBLIC_V4.some(([net, p]) => p === 0 || v4 >>> (32 - p) === net >>> (32 - p));
	}
	const v6 = parseIPv6(addr);
	if (v6 === null) {
		return false;
	}
	if (v6 >> 32n === 0xffffn) {
		return isPublicIP(v4String(Number(v6 & 0xffffffffn)));
	}
	// NAT64 well-known prefix 64:ff9b::/96 and 6to4 2002::/16: judged by the IPv4 part
	if (v6 >> 32n === 0x64ff9bn << 64n) {
		return isPublicIP(v4String(Number(v6 & 0xffffffffn)));
	}
	if (v6 >> 112n === 0x2002n) {
		return isPublicIP(v4String(Number((v6 >> 80n) & 0xffffffffn)));
	}
	return !NON_PUBLIC_V6.some(([net, p]) => v6 >> BigInt(128 - p) === net >> BigInt(128 - p));
};

const NON_PUBLIC_V4 = [
	["0.0.0.0", 8],
	["10.0.0.0", 8],
	["100.64.0.0", 10],
	["127.0.0.0", 8],
	["169.254.0.0", 16],
	["172.16.0.0", 12],
	["192.0.0.0", 24],
	["192.0.2.0", 24],
	["192.168.0.0", 16],
	["198.18.0.0", 15],
	["198.51.100.0", 24],
	["203.0.113.0", 24],
	["224.0.0.0", 4],
	["240.0.0.0", 4],
].map(([a, p]) => [parseIPv4(a), p]);

const NON_PUBLIC_V6 = [
	["::", 128],
	["::1", 128],
	["64:ff9b:1::", 48],
	["100::", 64],
	["2001::", 32], // Teredo
	["2001:db8::", 32],
	["fc00::", 7],
	["fe80::", 10],
	["ff00::", 8],
].map(([a, p]) => [parseIPv6(a), p]);

export {
	encodeNet,
	isPublicIP,
	normalizeCidrs,
	parseEntry,
	parseIPv4,
	parseIPv6,
	V6_MAPPED_PREFIX,
	V6_MAX,
	v4String,
	v6String,
};
