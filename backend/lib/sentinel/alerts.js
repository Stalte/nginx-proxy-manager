/**
 * Sentinel alerts: a message to a webhook, Discord, Slack, ntfy or Gotify when the
 * "under attack" mode of a host turns on or off.
 */

const TIMEOUT_MS = 10 * 1000;

/**
 * Text of an under-attack transition.
 *
 * @param   {Object} t  {host, on, manual, reason, until}
 * @returns {{title: string, text: string}}
 */
export const underAttackText = (t) => {
	if (t.on) {
		return {
			title: `Under attack mode ON: ${t.host}`,
			text: `Every visitor of ${t.host} must now pass a browser challenge. Reason: ${t.reason}. It stays on until the traffic has been normal for the whole activation period (at least until ${new Date(t.until).toISOString()}).`,
		};
	}
	return {
		title: `Under attack mode off: ${t.host}`,
		text: t.manual
			? `An administrator ended the under attack mode of ${t.host}. It was on since ${new Date(t.since).toISOString()} (${t.reason}).`
			: `The traffic of ${t.host} is back to normal, visitors are no longer challenged. It was on since ${new Date(t.since).toISOString()}.`,
	};
};

/**
 * Request for an alert: {url, init} for fetch().
 *
 * @param   {Object} cfg  {type, url, token}
 * @param   {Object} msg  {title, text, event, data}
 */
export const buildRequest = (cfg, msg) => {
	const json = (body) => ({
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
	switch (cfg.type) {
		case "discord":
			return { url: cfg.url, init: json({ content: `**${msg.title}**\n${msg.text}`.slice(0, 2000) }) };
		case "slack":
			return { url: cfg.url, init: json({ text: `*${msg.title}*\n${msg.text}` }) };
		case "ntfy": {
			const headers = { Title: msg.title.replace(/[^\x20-\x7e]/g, "?"), Tags: "shield", Priority: "high" };
			if (cfg.token) headers.Authorization = `Bearer ${cfg.token}`;
			return { url: cfg.url, init: { method: "POST", headers, body: msg.text } };
		}
		case "gotify": {
			const init = json({ title: msg.title, message: msg.text, priority: 8 });
			if (cfg.token) init.headers["X-Gotify-Key"] = cfg.token;
			return { url: cfg.url, init };
		}
		default: {
			const init = json({ event: msg.event, title: msg.title, text: msg.text, data: msg.data || {} });
			if (cfg.token) init.headers.Authorization = `Bearer ${cfg.token}`;
			return { url: cfg.url, init };
		}
	}
};

/**
 * Sends an alert. Throws when the service does not accept it.
 */
export const send = async (cfg, msg, fetchFn = fetch) => {
	const { url, init } = buildRequest(cfg, msg);
	const ctl = new AbortController();
	const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
	try {
		const res = await fetchFn(url, { ...init, redirect: "error", signal: ctl.signal });
		if (!res.ok) {
			throw new Error(`HTTP ${res.status}`);
		}
	} finally {
		clearTimeout(timer);
	}
};
