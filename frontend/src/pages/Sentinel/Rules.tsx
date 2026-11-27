import { IconArrowDown, IconArrowUp, IconEdit, IconTrash } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import {
	deleteSentinelRule,
	orderSentinelRules,
	type SentinelCondition,
	type SentinelList,
	type SentinelRule,
} from "src/api/backend";
import { Button, LoadingPage } from "src/components";
import { useInvalidateSentinel, useSentinelLists, useSentinelRules, useSetSentinelRule } from "src/hooks";
import { intl, T } from "src/locale";
import { showDeleteConfirmModal, showSentinelRuleModal } from "src/modals";
import { showError, showObjectSuccess } from "src/notifications";

const ACTION_COLOR: Record<string, string> = { block: "red", allow: "green", log: "blue", challenge: "orange" };

const describeCondition = (c: SentinelCondition, lists: SentinelList[]) => {
	const field =
		c.field === "http.header"
			? `${intl.formatMessage({ id: "sentinel.field.http.header" })} ${c.name}`
			: intl.formatMessage({ id: `sentinel.field.${c.field}` });
	const op = intl.formatMessage({ id: `sentinel.op.${c.operator}` });
	const values = (c.value || []).map((v) =>
		v.startsWith("list:") ? `[${lists.find((l) => l.id === Number(v.slice(5)))?.name || v}]` : v,
	);
	const shown = values.slice(0, 3).join(", ") + (values.length > 3 ? ` +${values.length - 3}` : "");
	return `${field} ${op}${shown ? ` ${shown}` : ""}`;
};

export default function Rules() {
	const { data, isLoading, isError, error, isFetching } = useSentinelRules();
	const lists = useSentinelLists();
	const { mutate: setRule } = useSetSentinelRule();
	const invalidate = useInvalidateSentinel();
	const [busy, setBusy] = useState(false);

	if (isLoading) {
		return <LoadingPage noLogo />;
	}
	if (isError) {
		return <Alert variant="danger">{error?.message || "Unknown error"}</Alert>;
	}
	const rules = data || [];

	const move = async (index: number, delta: number) => {
		const ids = rules.map((r) => r.id);
		const target = index + delta;
		if (target < 0 || target >= ids.length) return;
		[ids[index], ids[target]] = [ids[target], ids[index]];
		setBusy(true);
		try {
			await orderSentinelRules(ids);
		} catch (err: any) {
			showError(err.message);
		}
		invalidate();
		setBusy(false);
	};

	const toggle = (r: SentinelRule) =>
		setRule({ id: r.id, enabled: !r.enabled } as Partial<SentinelRule>, {
			onError: (err: any) => showError(err.message),
		});

	return (
		<>
			<div className="card-body border-bottom py-3 d-flex align-items-center flex-wrap gap-2">
				<div className="text-secondary small me-auto">
					<T id="sentinel.rules.hint" />
				</div>
				<Button size="sm" className="btn-red" onClick={() => showSentinelRuleModal("new")}>
					<T id="object.add" tData={{ object: "sentinel.rule" }} />
				</Button>
			</div>
			{rules.length === 0 ? (
				<div className="card-body text-center text-secondary py-5">
					<T id="sentinel.rules.empty" />
				</div>
			) : (
				<div className={cn("table-responsive", (isFetching || busy) && "opacity-75")}>
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th className="w-1">#</th>
								<th>
									<T id="column.name" />
								</th>
								<th>
									<T id="sentinel.rule.action" />
								</th>
								<th>
									<T id="sentinel.rule.conditions" />
								</th>
								<th>
									<T id="sentinel.rule.applies-to" />
								</th>
								<th className="w-1">
									<T id="sentinel.rule.enabled" />
								</th>
								<th className="w-1" />
							</tr>
						</thead>
						<tbody>
							{rules.map((r, i) => (
								<tr key={r.id} className={cn(!r.enabled && "text-secondary")}>
									<td className="text-nowrap">
										<button
											type="button"
											className="btn btn-sm btn-ghost-secondary btn-icon"
											disabled={i === 0 || busy}
											aria-label={intl.formatMessage({ id: "sentinel.rule.move-up" })}
											onClick={() => move(i, -1)}
										>
											<IconArrowUp size={14} />
										</button>
										<button
											type="button"
											className="btn btn-sm btn-ghost-secondary btn-icon"
											disabled={i === rules.length - 1 || busy}
											aria-label={intl.formatMessage({ id: "sentinel.rule.move-down" })}
											onClick={() => move(i, 1)}
										>
											<IconArrowDown size={14} />
										</button>
									</td>
									<td>
										<div className="fw-bold">{r.name}</div>
										{r.description ? (
											<div className="text-secondary small">{r.description}</div>
										) : null}
									</td>
									<td>
										<span className={`badge bg-${ACTION_COLOR[r.action]}-lt`}>
											<T id={`sentinel.action.${r.action}`} />
											{r.action === "block" ? ` · ${r.statusCode}` : ""}
										</span>
									</td>
									<td className="small" style={{ maxWidth: 420 }}>
										{r.expression.groups.map((g, gi) => (
											// biome-ignore lint/suspicious/noArrayIndexKey: groups have no id
											<div key={gi} className="text-truncate">
												{gi > 0 ? (
													<span className="badge bg-orange-lt me-1">
														<T id="sentinel.rule.or" />
													</span>
												) : null}
												{g
													.map((c) => describeCondition(c, lists.data || []))
													.join(` ${intl.formatMessage({ id: "sentinel.rule.and" })} `)}
											</div>
										))}
									</td>
									<td className="small">
										{r.scope === "all" ? (
											<T id="sentinel.scope.all" />
										) : (
											<T id="sentinel.scope.n-hosts" data={{ n: r.hostIds.length }} />
										)}
									</td>
									<td>
										<label className="form-check form-switch m-0">
											<input
												type="checkbox"
												className="form-check-input"
												checked={r.enabled}
												aria-label={intl.formatMessage({ id: "sentinel.rule.enabled" })}
												onChange={() => toggle(r)}
											/>
										</label>
									</td>
									<td className="text-nowrap">
										<button
											type="button"
											className="btn btn-sm btn-ghost-primary btn-icon"
											aria-label={intl.formatMessage({ id: "action.edit" })}
											onClick={() => showSentinelRuleModal(r.id)}
										>
											<IconEdit size={16} />
										</button>
										<button
											type="button"
											className="btn btn-sm btn-ghost-danger btn-icon"
											aria-label={intl.formatMessage({ id: "action.delete" })}
											onClick={() =>
												showDeleteConfirmModal({
													title: <T id="object.delete" tData={{ object: "sentinel.rule" }} />,
													onConfirm: async () => {
														await deleteSentinelRule(r.id);
														showObjectSuccess("sentinel.rule", "deleted");
													},
													invalidations: [["sentinel-rules"], ["sentinel-status"]],
													children: (
														<T
															id="object.delete.content"
															tData={{ object: "sentinel.rule" }}
														/>
													),
												})
											}
										>
											<IconTrash size={16} />
										</button>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</>
	);
}
