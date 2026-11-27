/**
 * Requests to the gateway's loopback status port (conf.d/sentinel.conf), authenticated
 * with the status key from /data/sentinel/secrets.json.
 */

import { PATHS } from "./compile.js";
import { ensureSecrets } from "./secrets.js";

const STATUS_URL = "http://127.0.0.1:9180";

export const statusRequest = async (path, init = {}) => {
	const { status_key: key } = ensureSecrets(PATHS.secrets);
	const ctl = new AbortController();
	const t = setTimeout(() => ctl.abort(), 5000);
	try {
		const res = await fetch(`${STATUS_URL}${path}`, {
			...init,
			headers: { ...(init.headers || {}), "X-Corvus-Status-Key": key },
			signal: ctl.signal,
		});
		if (!res.ok) {
			throw new Error(`status port answered HTTP ${res.status}`);
		}
		return res;
	} finally {
		clearTimeout(t);
	}
};
