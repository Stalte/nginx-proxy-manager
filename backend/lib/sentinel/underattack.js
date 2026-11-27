/**
 * Automatic part of the per proxy host "under attack" mode: activates the mode (every
 * visitor must pass a browser challenge) while a host's traffic is over its thresholds.
 *
 * Hysteresis: an activation lasts duration_s seconds after the last evaluation round in
 * which the host was still over a threshold, so it ends only once the traffic has stayed
 * below the thresholds for the whole period. A manual deactivation holds the host off
 * for one period, so it does not come straight back while the traffic is still high.
 *
 * Ported from Corvus (control/internal/underattack), Apache-2.0. Times are in ms.
 */

import { encodeNet } from "./ip.js";

// Least number of requests in the window before the blocked share is considered (a
// handful of blocked requests on an idle host is no attack).
export const MIN_RATIO_REQUESTS = 50;

// Client networks never challenged by the mode
export const EXEMPT = ["127.0.0.0/8", "::1/128"];

export const emptyState = () => ({ active: {}, hold: {} });

/**
 * Whether a host's traffic is over a threshold, and why.
 *
 * @param   {{r: number, b: number, secs: number}|undefined} t  traffic over the window
 * @param   {Object} c  host config {rps, blocked_pct}
 * @returns {[boolean, string]}
 */
export const over = (t, c) => {
	if (!t || !(t.secs > 0)) {
		return [false, ""];
	}
	const rps = t.r / t.secs;
	if (rps > c.rps) {
		return [true, `${Math.round(rps)} requests/s over ${t.secs} s (threshold ${c.rps})`];
	}
	if (c.blocked_pct > 0 && t.r >= MIN_RATIO_REQUESTS) {
		const share = (t.b * 100) / t.r;
		if (share >= c.blocked_pct) {
			return [
				true,
				`${Math.round(share)}% of ${t.r} requests blocked over ${t.secs} s (threshold ${c.blocked_pct}%)`,
			];
		}
	}
	return [false, ""];
};

/**
 * One evaluation round. Changes state in place and returns the transitions.
 *
 * @param   {Object}   state    {active: {id: {host, since, until, reason}}, hold: {id: until}}
 * @param   {Object[]} hosts    enabled proxy hosts in auto mode: {id, host, config}
 * @param   {Function} traffic  (id, window_s) → {r, b, secs} | undefined
 * @param   {number}   now
 * @returns {{changed: boolean, transitions: Object[]}}
 */
export const evaluate = (state, hosts, traffic, now) => {
	let changed = false;
	const transitions = [];
	const seen = new Set();
	for (const h of hosts) {
		const id = String(h.id);
		seen.add(id);
		const period = h.config.duration_s * 1000;
		const [hot, why] = over(traffic(h.id, h.config.window_s), h.config);
		const a = state.active[id];
		if (a && hot) {
			a.until = now + period;
			a.host = h.host;
			changed = true;
		} else if (a && now >= a.until) {
			delete state.active[id];
			changed = true;
			transitions.push({
				id: h.id,
				host: h.host,
				on: false,
				reason: a.reason,
				since: a.since,
				until: a.until,
				at: now,
			});
		} else if (!a && hot) {
			if (state.hold[id] && now < state.hold[id]) {
				continue;
			}
			const n = { host: h.host, since: now, until: now + period, reason: why };
			state.active[id] = n;
			changed = true;
			transitions.push({ id: h.id, host: h.host, on: true, reason: why, since: now, until: n.until, at: now });
		}
	}
	// hosts deleted, disabled or switched away from auto: their activation ends silently
	for (const id of Object.keys(state.active)) {
		if (!seen.has(id)) {
			delete state.active[id];
			changed = true;
		}
	}
	for (const [id, t] of Object.entries(state.hold)) {
		if (now >= t || !seen.has(id)) {
			delete state.hold[id];
			changed = true;
		}
	}
	return { changed, transitions };
};

/**
 * Ends an automatic activation now and holds the host off for one period.
 *
 * @returns {Object|null}  the transition, or null when the host was not active
 */
export const deactivate = (state, id, durationS, now) => {
	const a = state.active[String(id)];
	if (!a) {
		return null;
	}
	delete state.active[String(id)];
	state.hold[String(id)] = now + durationS * 1000;
	return {
		id: Number(id),
		host: a.host,
		on: false,
		manual: true,
		reason: a.reason,
		since: a.since,
		until: a.until,
		at: now,
	};
};

/**
 * Body of PUT /under-attack on the gateway's status port: it replaces the gateway's set.
 * {"hosts": {"<proxy host id>": <activation ends, unix s>}, "exempt": ["<hex net>/<prefix>"]}
 */
export const payload = (state, now) => {
	const hosts = {};
	for (const [id, a] of Object.entries(state.active)) {
		if (now < a.until) {
			hosts[id] = Math.floor(a.until / 1000);
		}
	}
	return { hosts, exempt: EXEMPT.map(encodeNet) };
};

/**
 * Reads the stored state; anything unreadable starts empty.
 */
export const parseState = (raw) => {
	try {
		const v = JSON.parse(raw);
		return {
			active: v && typeof v.active === "object" && v.active ? v.active : {},
			hold: v && typeof v.hold === "object" && v.hold ? v.hold : {},
		};
	} catch {
		return emptyState();
	}
};
