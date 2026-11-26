import { IconEdit, IconRefresh, IconTrash } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Dropdown from "react-bootstrap/Dropdown";
import { deleteSentinelList, refreshSentinelList } from "src/api/backend";
import { Button, LoadingPage } from "src/components";
import { useInvalidateSentinel, useSentinelLists } from "src/hooks";
import { formatDateTime, getLocale, intl, T } from "src/locale";
import { SENTINEL_LIST_PRESETS, sentinelPreset, showDeleteConfirmModal, showSentinelListModal } from "src/modals";
import { showError, showObjectSuccess, showSuccess } from "src/notifications";

export default function Lists() {
	const { data, isLoading, isError, error, isFetching } = useSentinelLists();
	const invalidate = useInvalidateSentinel();
	const [refreshing, setRefreshing] = useState<number | null>(null);

	if (isLoading) {
		return <LoadingPage noLogo />;
	}
	if (isError) {
		return <Alert variant="danger">{error?.message || "Unknown error"}</Alert>;
	}
	const lists = data || [];

	const refresh = async (id: number) => {
		setRefreshing(id);
		try {
			const l = await refreshSentinelList(id);
			showSuccess(intl.formatMessage({ id: "sentinel.list.refreshed" }, { n: l.itemCount ?? 0 }));
		} catch (err: any) {
			showError(err.message);
		}
		invalidate();
		setRefreshing(null);
	};

	return (
		<>
			<div className="card-body border-bottom py-3 d-flex align-items-center flex-wrap gap-2">
				<div className="text-secondary small me-auto">
					<T id="sentinel.lists.hint" />
				</div>
				<Dropdown>
					<Dropdown.Toggle size="sm" variant="outline-secondary">
						<T id="sentinel.presets" />
					</Dropdown.Toggle>
					<Dropdown.Menu>
						{SENTINEL_LIST_PRESETS.map((p) => (
							<Dropdown.Item
								key={p.id}
								onClick={() => showSentinelListModal("new", sentinelPreset(p.id))}
							>
								<T id={`sentinel.preset.${p.id}`} />
							</Dropdown.Item>
						))}
					</Dropdown.Menu>
				</Dropdown>
				<Button size="sm" className="btn-red" onClick={() => showSentinelListModal("new")}>
					<T id="object.add" tData={{ object: "sentinel.list" }} />
				</Button>
			</div>
			{lists.length === 0 ? (
				<div className="card-body text-center text-secondary py-5">
					<T id="sentinel.lists.empty" />
				</div>
			) : (
				<div className={cn("table-responsive", isFetching && "opacity-75")}>
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="column.name" />
								</th>
								<th>
									<T id="sentinel.list.kind" />
								</th>
								<th>
									<T id="sentinel.list.source" />
								</th>
								<th className="text-end">
									<T id="sentinel.list.entries" />
								</th>
								<th className="w-1" />
							</tr>
						</thead>
						<tbody>
							{lists.map((l) => (
								<tr key={l.id}>
									<td>
										<div className="fw-bold">{l.name}</div>
										{l.description ? (
											<div className="text-secondary small">{l.description}</div>
										) : null}
									</td>
									<td>
										<span className={cn("badge", l.kind === "ip" ? "bg-cyan-lt" : "bg-purple-lt")}>
											<T id={`sentinel.list.kind.${l.kind}`} />
										</span>
									</td>
									<td className="small" style={{ maxWidth: 360 }}>
										{l.sourceUrl ? (
											<>
												<div className="text-truncate font-monospace" title={l.sourceUrl}>
													{l.sourceUrl}
												</div>
												<div className="text-secondary">
													{l.fetchedOn ? (
														<T
															id="sentinel.list.fetched"
															data={{ date: formatDateTime(l.fetchedOn, getLocale()) }}
														/>
													) : (
														<T id="sentinel.list.not-fetched" />
													)}
												</div>
												{l.fetchError ? (
													<div className="text-warning text-truncate" title={l.fetchError}>
														{l.fetchError}
													</div>
												) : null}
											</>
										) : (
											<T id="sentinel.list.source.manual" />
										)}
									</td>
									<td className="text-end">{(l.itemCount ?? 0).toLocaleString(getLocale())}</td>
									<td className="text-nowrap">
										{l.sourceUrl ? (
											<button
												type="button"
												className="btn btn-sm btn-ghost-secondary btn-icon"
												disabled={refreshing !== null}
												aria-label={intl.formatMessage({ id: "sentinel.list.refresh-now" })}
												title={intl.formatMessage({ id: "sentinel.list.refresh-now" })}
												onClick={() => refresh(l.id)}
											>
												<IconRefresh
													size={16}
													className={cn(refreshing === l.id && "spinner-border-sm")}
												/>
											</button>
										) : null}
										<button
											type="button"
											className="btn btn-sm btn-ghost-primary btn-icon"
											aria-label={intl.formatMessage({ id: "action.edit" })}
											onClick={() => showSentinelListModal(l.id)}
										>
											<IconEdit size={16} />
										</button>
										<button
											type="button"
											className="btn btn-sm btn-ghost-danger btn-icon"
											aria-label={intl.formatMessage({ id: "action.delete" })}
											onClick={() =>
												showDeleteConfirmModal({
													title: <T id="object.delete" tData={{ object: "sentinel.list" }} />,
													onConfirm: async () => {
														await deleteSentinelList(l.id);
														showObjectSuccess("sentinel.list", "deleted");
													},
													invalidations: [["sentinel-lists"], ["sentinel-status"]],
													children: (
														<T
															id="object.delete.content"
															tData={{ object: "sentinel.list" }}
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
