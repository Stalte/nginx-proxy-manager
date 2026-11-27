/**
 * Keys of the gateway: the signing key of challenge passes, and the key of the loopback
 * status port. Generated once and kept in /data/sentinel/secrets.json (readable by root
 * only), so passes stay valid across restarts and upgrades. nginx reads the file in
 * init_by_lua (/etc/nginx/lua/corvus/rules.lua).
 */

import crypto from "node:crypto";
import fs from "node:fs";

let cached = null;

/**
 * @param   {string} file
 * @returns {{key: string, status_key: string}}
 */
export const ensureSecrets = (file) => {
	if (cached?.file === file) {
		return cached.value;
	}
	let value = null;
	try {
		const v = JSON.parse(fs.readFileSync(file, "utf8"));
		if (typeof v.key === "string" && v.key.length >= 32 && typeof v.status_key === "string" && v.status_key) {
			value = v;
		}
	} catch {
		// first start, or unreadable: write new keys
	}
	if (!value) {
		value = { key: crypto.randomBytes(32).toString("hex"), status_key: crypto.randomBytes(32).toString("hex") };
		const tmp = `${file}.tmp`;
		fs.writeFileSync(tmp, JSON.stringify(value), { mode: 0o600 });
		fs.renameSync(tmp, file);
	}
	fs.chmodSync(file, 0o600);
	cached = { file, value };
	return value;
};
