import * as api from "./base";

export type SentinelAction = "block" | "allow" | "log" | "challenge";
export type SentinelField =
	| "ip.src"
	| "ip.country"
	| "http.method"
	| "http.scheme"
	| "http.host"
	| "http.path"
	| "http.query"
	| "http.user_agent"
	| "http.user_agent_list"
	| "http.referer"
	| "http.header";
export type SentinelOperator =
	| "eq"
	| "ne"
	| "contains"
	| "not_contains"
	| "starts_with"
	| "ends_with"
	| "matches"
	| "not_matches"
	| "in"
	| "not_in"
	| "exists"
	| "not_exists";

export interface SentinelCondition {
	field: SentinelField;
	operator: SentinelOperator;
	name?: string;
	value: string[];
	ci?: boolean;
}

export interface SentinelChallenge {
	mode: "js" | "cookie";
	difficulty: number;
	ttl: number;
	bind: "ip" | "ip_ua";
}

export interface SentinelRule {
	id: number;
	createdOn?: string;
	modifiedOn?: string;
	name: string;
	description: string;
	enabled: boolean;
	position?: number;
	action: SentinelAction;
	statusCode: number;
	challenge?: SentinelChallenge | null;
	scope: "all" | "hosts";
	hostIds: number[];
	expression: { groups: SentinelCondition[][] };
}

export type SentinelListKind = "ip" | "user_agent";

export interface SentinelList {
	id: number;
	createdOn?: string;
	modifiedOn?: string;
	name: string;
	description: string;
	kind: SentinelListKind;
	sourceUrl: string;
	refreshS: number;
	items?: string[];
	itemCount?: number;
	fetchedOn?: string | null;
	changedOn?: string | null;
	fetchError?: string;
}

export interface SentinelStatus {
	deploy: { ok: boolean; error: string; at: string | null; rules: number };
	geoip: {
		available: boolean;
		updatedOn: string | null;
		ranges: number;
		attribution: string;
		downloading: boolean;
		error: string;
	};
	underAttack?: { active: number; sync: { ok: boolean; error: string; at: string | null } };
}

export type SentinelUnderAttackMode = "off" | "on" | "auto";

export interface SentinelUnderAttackConfig extends SentinelChallenge {
	rps: number;
	blockedPct: number;
	windowS: number;
	durationS: number;
}

export interface SentinelUnderAttackHost {
	proxyHostId: number;
	domainNames: string[];
	enabled: boolean;
	underAttack: SentinelUnderAttackMode;
	config: SentinelUnderAttackConfig;
	active: boolean;
	since: string | null;
	until: string | null;
	reason: string;
}

export interface SentinelUnderAttackEvent {
	id: number;
	host: string;
	on: boolean;
	manual?: boolean;
	reason: string;
	at: string;
}

export type SentinelAlertType = "webhook" | "discord" | "slack" | "ntfy" | "gotify";

export interface SentinelAlerts {
	enabled: boolean;
	type: SentinelAlertType;
	url: string;
	token: string;
	hasToken?: boolean;
	clearToken?: boolean;
	last?: { at: string | null; ok: boolean; error: string };
}

// Condition values are data, not keys: send them as they are (the API client converts
// object keys to snake_case, which only touches the keys).
const rulePayload = (r: Partial<SentinelRule>) => {
	const { id: _id, createdOn: _c, modifiedOn: _m, position: _p, ...rest } = r;
	return rest;
};

export async function getSentinelStatus(): Promise<SentinelStatus> {
	return await api.get({ url: "/sentinel/status" });
}

export async function getSentinelRules(): Promise<SentinelRule[]> {
	return await api.get({ url: "/sentinel/rules" });
}

export async function getSentinelRule(id: number): Promise<SentinelRule> {
	return await api.get({ url: `/sentinel/rules/${id}` });
}

export async function saveSentinelRule(rule: Partial<SentinelRule>): Promise<SentinelRule> {
	if (rule.id) {
		return await api.put({ url: `/sentinel/rules/${rule.id}`, data: rulePayload(rule) });
	}
	return await api.post({ url: "/sentinel/rules", data: rulePayload(rule) });
}

export async function deleteSentinelRule(id: number): Promise<boolean> {
	return await api.del({ url: `/sentinel/rules/${id}` });
}

export async function orderSentinelRules(ids: number[]): Promise<SentinelRule[]> {
	return await api.put({ url: "/sentinel/rules/order", data: { ids } });
}

export async function getSentinelLists(): Promise<SentinelList[]> {
	return await api.get({ url: "/sentinel/lists" });
}

export async function getSentinelList(id: number): Promise<SentinelList> {
	return await api.get({ url: `/sentinel/lists/${id}` });
}

export async function saveSentinelList(list: Partial<SentinelList>): Promise<SentinelList> {
	const data = {
		name: list.name,
		description: list.description,
		kind: list.kind,
		sourceUrl: list.sourceUrl,
		refreshS: list.refreshS,
		items: list.sourceUrl ? [] : list.items,
	};
	if (list.id) {
		const { kind: _k, ...update } = data;
		return await api.put({ url: `/sentinel/lists/${list.id}`, data: update });
	}
	return await api.post({ url: "/sentinel/lists", data });
}

export async function deleteSentinelList(id: number): Promise<boolean> {
	return await api.del({ url: `/sentinel/lists/${id}` });
}

export async function refreshSentinelList(id: number): Promise<SentinelList> {
	return await api.post({ url: `/sentinel/lists/${id}/refresh` });
}

export async function getSentinelUnderAttack(): Promise<SentinelUnderAttackHost[]> {
	return await api.get({ url: "/sentinel/under-attack" });
}

export async function getSentinelUnderAttackEvents(): Promise<SentinelUnderAttackEvent[]> {
	return await api.get({ url: "/sentinel/under-attack/events" });
}

export async function saveSentinelUnderAttack(
	hostId: number,
	underAttack: SentinelUnderAttackMode,
	config: SentinelUnderAttackConfig,
): Promise<SentinelUnderAttackHost> {
	return await api.put({ url: `/sentinel/under-attack/${hostId}`, data: { underAttack, config } });
}

export async function deactivateSentinelUnderAttack(hostId: number): Promise<boolean> {
	return await api.post({ url: `/sentinel/under-attack/${hostId}/deactivate` });
}

export async function getSentinelAlerts(): Promise<SentinelAlerts> {
	return await api.get({ url: "/sentinel/alerts" });
}

export async function saveSentinelAlerts(a: SentinelAlerts): Promise<SentinelAlerts> {
	const data: Record<string, unknown> = { enabled: a.enabled, type: a.type, url: a.url };
	if (a.token) data.token = a.token;
	if (a.clearToken) data.clearToken = true;
	return await api.put({ url: "/sentinel/alerts", data });
}

export async function testSentinelAlerts(): Promise<boolean> {
	return await api.post({ url: "/sentinel/alerts/test" });
}
