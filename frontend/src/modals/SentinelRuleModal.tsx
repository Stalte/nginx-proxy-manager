import { IconPlus, IconTrash } from "@tabler/icons-react";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import type {
	SentinelAction,
	SentinelCondition,
	SentinelField,
	SentinelList,
	SentinelOperator,
	SentinelRule,
} from "src/api/backend";
import { Button, Loading } from "src/components";
import { useProxyHosts, useSentinelLists, useSentinelRules, useSetSentinelRule } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";
import { DEFAULT_CHALLENGE, SentinelChallengeFields } from "./SentinelChallengeFields";

const SET_OPS: SentinelOperator[] = ["in", "not_in"];
const STRING_OPS: SentinelOperator[] = [
	"eq",
	"ne",
	"contains",
	"not_contains",
	"starts_with",
	"ends_with",
	"matches",
	"not_matches",
	"in",
	"not_in",
];
const EXISTS_OPS: SentinelOperator[] = ["exists", "not_exists"];

// Fields a condition can test, with the operators that apply
export const SENTINEL_FIELDS: { field: SentinelField; ops: SentinelOperator[] }[] = [
	{ field: "ip.src", ops: SET_OPS },
	{ field: "ip.country", ops: SET_OPS },
	{ field: "http.path", ops: STRING_OPS },
	{ field: "http.query", ops: STRING_OPS },
	{ field: "http.method", ops: SET_OPS },
	{ field: "http.host", ops: STRING_OPS },
	{ field: "http.header", ops: [...STRING_OPS, ...EXISTS_OPS] },
	{ field: "http.user_agent", ops: [...STRING_OPS, ...EXISTS_OPS] },
	{ field: "http.user_agent_list", ops: SET_OPS },
	{ field: "http.referer", ops: [...STRING_OPS, ...EXISTS_OPS] },
	{ field: "http.scheme", ops: SET_OPS },
];

const STATUS_CODES = [403, 401, 404, 410, 429, 444];
const STRING_FIELDS: SentinelField[] = [
	"http.path",
	"http.query",
	"http.host",
	"http.header",
	"http.user_agent",
	"http.referer",
];

interface CondState {
	field: SentinelField;
	operator: SentinelOperator;
	name: string;
	text: string;
	lists: number[];
	ci: boolean;
}

const blankCond = (): CondState => ({ field: "ip.src", operator: "in", name: "", text: "", lists: [], ci: false });

// Values separated by lines, and also by commas for codes and methods
const splitValues = (field: SentinelField, operator: SentinelOperator, text: string): string[] => {
	if (!SET_OPS.includes(operator)) {
		return text.trim() === "" ? [] : [text.trim()];
	}
	const sep = ["ip.country", "http.method", "http.scheme"].includes(field) ? /[\s,]+/ : /\r?\n/;
	return text
		.split(sep)
		.map((s) => s.trim())
		.filter(Boolean);
};

const toState = (c: SentinelCondition): CondState => {
	const lists = (c.value || []).filter((v) => v.startsWith("list:")).map((v) => Number(v.slice(5)));
	const plain = (c.value || []).filter((v) => !v.startsWith("list:"));
	const sep = ["ip.country", "http.method", "http.scheme"].includes(c.field) ? ", " : "\n";
	return { field: c.field, operator: c.operator, name: c.name || "", text: plain.join(sep), lists, ci: !!c.ci };
};

const toCondition = (s: CondState): SentinelCondition => {
	const c: SentinelCondition = { field: s.field, operator: s.operator, value: [] };
	if (s.field === "http.header") c.name = s.name.trim();
	if (EXISTS_OPS.includes(s.operator)) return c;
	c.value = [...splitValues(s.field, s.operator, s.text), ...s.lists.map((id) => `list:${id}`)];
	if (s.ci && STRING_FIELDS.includes(s.field)) c.ci = true;
	return c;
};

const showSentinelRuleModal = (id: number | "new") => {
	EasyModal.show(SentinelRuleModal, { ruleId: id });
};

interface Props extends InnerModalProps {
	ruleId: number | "new";
}

const SentinelRuleModal = EasyModal.create(({ ruleId: id, visible, remove }: Props) => {
	const rules = useSentinelRules();
	const lists = useSentinelLists();
	const hosts = useProxyHosts();
	if (rules.isLoading || lists.isLoading || hosts.isLoading) {
		return (
			<Modal show={visible} onHide={remove}>
				<Loading noLogo />
			</Modal>
		);
	}
	const rule = id === "new" ? undefined : rules.data?.find((r) => r.id === id);
	return (
		<RuleForm
			rule={rule}
			lists={lists.data || []}
			hosts={(hosts.data || []).map((h) => ({ id: h.id, name: h.domainNames.join(", ") }))}
			visible={visible}
			remove={remove}
		/>
	);
});

interface FormProps {
	rule?: SentinelRule;
	lists: SentinelList[];
	hosts: { id: number; name: string }[];
	visible: boolean;
	remove: () => void;
}

function RuleForm({ rule, lists, hosts, visible, remove }: FormProps) {
	const { mutate: setRule } = useSetSentinelRule();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [name, setName] = useState(rule?.name || "");
	const [description, setDescription] = useState(rule?.description || "");
	const [action, setAction] = useState<SentinelAction>(rule?.action || "block");
	const [statusCode, setStatusCode] = useState(rule?.statusCode || 403);
	const [challenge, setChallenge] = useState(rule?.challenge || DEFAULT_CHALLENGE);
	const [enabled, setEnabled] = useState(rule ? rule.enabled : true);
	const [scope, setScope] = useState<"all" | "hosts">(rule?.scope || "all");
	const [hostIds, setHostIds] = useState<number[]>(rule?.hostIds || []);
	const [groups, setGroups] = useState<CondState[][]>(
		rule?.expression?.groups?.length ? rule.expression.groups.map((g) => g.map(toState)) : [[blankCond()]],
	);

	const ipLists = lists.filter((l) => l.kind === "ip");
	const uaLists = lists.filter((l) => l.kind === "user_agent");

	const setCond = (gi: number, ci: number, p: Partial<CondState>) =>
		setGroups((gs) => gs.map((g, i) => (i !== gi ? g : g.map((c, j) => (j !== ci ? c : { ...c, ...p })))));
	const addCond = (gi: number) => setGroups((gs) => gs.map((g, i) => (i !== gi ? g : [...g, blankCond()])));
	const removeCond = (gi: number, ci: number) =>
		setGroups((gs) => gs.map((g, i) => (i !== gi ? g : g.filter((_, j) => j !== ci))).filter((g) => g.length));

	const onField = (gi: number, ci: number, field: SentinelField) => {
		const ops = SENTINEL_FIELDS.find((f) => f.field === field)?.ops || SET_OPS;
		const current = groups[gi][ci].operator;
		setCond(gi, ci, { field, operator: ops.includes(current) ? current : ops[0], lists: [], text: "" });
	};

	const onSubmit = (e: React.FormEvent) => {
		e.preventDefault();
		if (isSubmitting) return;
		setIsSubmitting(true);
		setErrorMsg(null);
		const payload: Partial<SentinelRule> = {
			id: rule?.id,
			name: name.trim(),
			description: description.trim(),
			enabled,
			action,
			statusCode: action === "block" ? statusCode : 403,
			challenge: action === "challenge" ? challenge : null,
			scope,
			hostIds: scope === "hosts" ? hostIds : [],
			expression: { groups: groups.map((g) => g.map(toCondition)) },
		};
		setRule(payload, {
			onError: (err: any) => setErrorMsg(err.message),
			onSuccess: () => {
				showObjectSuccess("sentinel.rule", "saved");
				remove();
			},
			onSettled: () => setIsSubmitting(false),
		});
	};

	const listPicker = (gi: number, ci: number, c: CondState, choices: SentinelList[]) =>
		choices.length ? (
			<div className="mt-2">
				{choices.map((l) => (
					<label key={l.id} className="form-check form-check-inline mb-1">
						<input
							type="checkbox"
							className="form-check-input"
							checked={c.lists.includes(l.id)}
							onChange={(e) =>
								setCond(gi, ci, {
									lists: e.target.checked ? [...c.lists, l.id] : c.lists.filter((x) => x !== l.id),
								})
							}
						/>
						<span className="form-check-label">{l.name}</span>
					</label>
				))}
			</div>
		) : (
			<div className="text-secondary small mt-2">
				<T id="sentinel.rule.no-lists" />
			</div>
		);

	const valueInput = (gi: number, ci: number, c: CondState) => {
		if (EXISTS_OPS.includes(c.operator)) return null;
		if (c.field === "http.user_agent_list") return listPicker(gi, ci, c, uaLists);
		const multi = SET_OPS.includes(c.operator) && !["ip.country", "http.method", "http.scheme"].includes(c.field);
		const placeholder = intl.formatMessage({ id: `sentinel.placeholder.${c.field}` });
		return (
			<>
				{multi ? (
					<textarea
						className="form-control form-control-sm font-monospace"
						rows={c.field === "ip.src" ? 3 : 2}
						placeholder={placeholder}
						value={c.text}
						onChange={(e) => setCond(gi, ci, { text: e.target.value })}
					/>
				) : (
					<input
						className="form-control form-control-sm font-monospace"
						placeholder={placeholder}
						value={c.text}
						onChange={(e) => setCond(gi, ci, { text: e.target.value })}
					/>
				)}
				{c.field === "ip.src" && listPicker(gi, ci, c, ipLists)}
			</>
		);
	};

	return (
		<Modal show={visible} onHide={isSubmitting ? undefined : remove} size="xl">
			<form onSubmit={onSubmit}>
				<Modal.Header closeButton>
					<Modal.Title>
						<T id={rule ? "object.edit" : "object.add"} tData={{ object: "sentinel.rule" }} />
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
						{errorMsg}
					</Alert>
					<div className="row">
						<div className="col-md-6 mb-3">
							<label htmlFor="sr-name" className="form-label required">
								<T id="column.name" />
							</label>
							<input
								id="sr-name"
								className="form-control"
								required
								maxLength={100}
								value={name}
								onChange={(e) => setName(e.target.value)}
							/>
						</div>
						<div className="col-md-3 mb-3">
							<label htmlFor="sr-action" className="form-label">
								<T id="sentinel.rule.action" />
							</label>
							<select
								id="sr-action"
								className="form-select"
								value={action}
								onChange={(e) => setAction(e.target.value as SentinelAction)}
							>
								{(["block", "challenge", "allow", "log"] as SentinelAction[]).map((a) => (
									<option key={a} value={a}>
										{intl.formatMessage({ id: `sentinel.action.${a}` })}
									</option>
								))}
							</select>
						</div>
						<div className="col-md-3 mb-3">
							<label htmlFor="sr-status" className="form-label">
								<T id="sentinel.rule.status" />
							</label>
							<select
								id="sr-status"
								className="form-select"
								value={statusCode}
								disabled={action !== "block"}
								onChange={(e) => setStatusCode(Number(e.target.value))}
							>
								{STATUS_CODES.map((s) => (
									<option key={s} value={s}>
										{intl.formatMessage({ id: `sentinel.status.${s}` })}
									</option>
								))}
							</select>
						</div>
					</div>
					<div className="mb-2 text-secondary small">
						<T id={`sentinel.action.${action}.hint`} />
					</div>
					{action === "challenge" ? (
						<SentinelChallengeFields idPrefix="sr-ch" value={challenge} onChange={setChallenge} />
					) : null}
					<div className="mb-3">
						<label htmlFor="sr-desc" className="form-label">
							<T id="sentinel.description" />
						</label>
						<input
							id="sr-desc"
							className="form-control"
							maxLength={500}
							value={description}
							onChange={(e) => setDescription(e.target.value)}
						/>
					</div>

					<h4 className="mt-4 mb-2">
						<T id="sentinel.rule.when" />
					</h4>
					{groups.map((g, gi) => (
						// biome-ignore lint/suspicious/noArrayIndexKey: groups have no id
						<div key={gi}>
							{gi > 0 && (
								<div className="text-center my-2">
									<span className="badge bg-orange-lt text-uppercase">
										<T id="sentinel.rule.or" />
									</span>
								</div>
							)}
							<div className="card card-sm">
								<div className="card-body">
									{g.map((c, ci) => {
										const ops = SENTINEL_FIELDS.find((f) => f.field === c.field)?.ops || SET_OPS;
										return (
											// biome-ignore lint/suspicious/noArrayIndexKey: conditions have no id
											<div key={ci} className="row g-2 align-items-start mb-2">
												<div className="col-md-1 pt-1 text-secondary small text-uppercase">
													{ci === 0 ? (
														<T id="sentinel.rule.if" />
													) : (
														<T id="sentinel.rule.and" />
													)}
												</div>
												<div className="col-md-3">
													<select
														className="form-select form-select-sm"
														aria-label={intl.formatMessage({ id: "sentinel.rule.field" })}
														value={c.field}
														onChange={(e) =>
															onField(gi, ci, e.target.value as SentinelField)
														}
													>
														{SENTINEL_FIELDS.map((f) => (
															<option key={f.field} value={f.field}>
																{intl.formatMessage({
																	id: `sentinel.field.${f.field}`,
																})}
															</option>
														))}
													</select>
													{c.field === "http.header" && (
														<input
															className="form-control form-control-sm mt-1"
															placeholder={intl.formatMessage({
																id: "sentinel.rule.header-name",
															})}
															value={c.name}
															onChange={(e) => setCond(gi, ci, { name: e.target.value })}
														/>
													)}
												</div>
												<div className="col-md-2">
													<select
														className="form-select form-select-sm"
														aria-label={intl.formatMessage({
															id: "sentinel.rule.operator",
														})}
														value={c.operator}
														onChange={(e) =>
															setCond(gi, ci, {
																operator: e.target.value as SentinelOperator,
															})
														}
													>
														{ops.map((o) => (
															<option key={o} value={o}>
																{intl.formatMessage({ id: `sentinel.op.${o}` })}
															</option>
														))}
													</select>
													{STRING_FIELDS.includes(c.field) &&
														!EXISTS_OPS.includes(c.operator) && (
															<label className="form-check mt-1 mb-0 small">
																<input
																	type="checkbox"
																	className="form-check-input"
																	checked={c.ci}
																	onChange={(e) =>
																		setCond(gi, ci, { ci: e.target.checked })
																	}
																/>
																<span className="form-check-label">
																	<T id="sentinel.rule.ignore-case" />
																</span>
															</label>
														)}
												</div>
												<div className="col-md-5">{valueInput(gi, ci, c)}</div>
												<div className="col-md-1 text-end">
													<button
														type="button"
														className="btn btn-sm btn-ghost-danger btn-icon"
														aria-label={intl.formatMessage({ id: "action.delete" })}
														onClick={() => removeCond(gi, ci)}
													>
														<IconTrash size={16} />
													</button>
												</div>
											</div>
										);
									})}
									<button
										type="button"
										className="btn btn-sm btn-ghost-primary"
										onClick={() => addCond(gi)}
									>
										<IconPlus size={16} className="me-1" />
										<T id="sentinel.rule.add-and" />
									</button>
								</div>
							</div>
						</div>
					))}
					<button
						type="button"
						className="btn btn-sm btn-outline-orange mt-2"
						disabled={groups.length >= 10}
						onClick={() => setGroups((gs) => [...gs, [blankCond()]])}
					>
						<IconPlus size={16} className="me-1" />
						<T id="sentinel.rule.add-or" />
					</button>

					<h4 className="mt-4 mb-2">
						<T id="sentinel.rule.applies-to" />
					</h4>
					<div className="btn-group mb-2" role="group">
						<input
							type="radio"
							className="btn-check"
							id="sr-scope-all"
							checked={scope === "all"}
							onChange={() => setScope("all")}
						/>
						<label htmlFor="sr-scope-all" className="btn btn-sm">
							<T id="sentinel.scope.all" />
						</label>
						<input
							type="radio"
							className="btn-check"
							id="sr-scope-hosts"
							checked={scope === "hosts"}
							onChange={() => setScope("hosts")}
						/>
						<label htmlFor="sr-scope-hosts" className="btn btn-sm">
							<T id="sentinel.scope.hosts" />
						</label>
					</div>
					{scope === "hosts" && (
						<div className="border rounded p-2" style={{ maxHeight: 180, overflowY: "auto" }}>
							{hosts.length ? (
								hosts.map((h) => (
									<label key={h.id} className="form-check mb-1">
										<input
											type="checkbox"
											className="form-check-input"
											checked={hostIds.includes(h.id)}
											onChange={(e) =>
												setHostIds((ids) =>
													e.target.checked ? [...ids, h.id] : ids.filter((x) => x !== h.id),
												)
											}
										/>
										<span className="form-check-label">{h.name}</span>
									</label>
								))
							) : (
								<span className="text-secondary small">
									<T id="sentinel.rule.no-hosts" />
								</span>
							)}
						</div>
					)}
					<div className="text-secondary small mt-1">
						<T id="sentinel.scope.hint" />
					</div>

					<label className="form-check form-switch mt-4">
						<input
							type="checkbox"
							className="form-check-input"
							checked={enabled}
							onChange={(e) => setEnabled(e.target.checked)}
						/>
						<span className="form-check-label">
							<T id="sentinel.rule.enabled" />
						</span>
					</label>
				</Modal.Body>
				<Modal.Footer>
					<Button onClick={remove} disabled={isSubmitting}>
						<T id="cancel" />
					</Button>
					<Button
						type="submit"
						actionType="primary"
						className="ms-auto bg-red"
						isLoading={isSubmitting}
						disabled={isSubmitting}
					>
						<T id="save" />
					</Button>
				</Modal.Footer>
			</form>
		</Modal>
	);
}

export { showSentinelRuleModal };
