import * as api from "./base";

export type SentinelAction = "block" | "allow" | "log";
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
