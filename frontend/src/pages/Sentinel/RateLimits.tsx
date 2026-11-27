import { IconEdit, IconTrash } from "@tabler/icons-react";
import cn from "classnames";
import Alert from "react-bootstrap/Alert";
import { deleteSentinelRateLimit, type SentinelRateLimit } from "src/api/backend";
import { Button, LoadingPage } from "src/components";
import { useProxyHosts, useSentinelRateLimits } from "src/hooks";
import { intl, T } from "src/locale";
import { showDeleteConfirmModal, showSentinelRateLimitModal } from "src/modals";
import { showObjectSuccess } from "src/notifications";

export default function RateLimits() {
	const { data, isLoading, isError, error, isFetching } = useSentinelRateLimits({ refetchInterval: 30 * 1000 });
	const hosts = useProxyHosts();

	if (isLoading) {
		return <LoadingPage noLogo />;
	}
	if (isError) {
		return <Alert variant="danger">{error?.message || "Unknown error"}</Alert>;
	}
	const policies = data || [];
	const hostName = (id: number) => hosts.data?.find((h) => h.id === id)?.domainNames[0] || `#${id}`;

	const remove = (r: SentinelRateLimit) =>
		showDeleteConfirmModal({
			title: <T id="object.delete" tData={{ object: "sentinel.rate-limit" }} />,
			onConfirm: async () => {
				await deleteSentinelRateLimit(r.id);
				showObjectSuccess("sentinel.rate-limit", "deleted");
			},
			invalidations: [["sentinel-rate-limits"], ["sentinel-under-attack"]],
			children: <T id="object.delete.content" tData={{ object: "sentinel.rate-limit" }} />,
		});

	return (
		<>
			<div className="card-body border-bottom py-3 d-flex align-items-center flex-wrap gap-2">
				<div className="text-secondary small me-auto">
					<T id="sentinel.rate-limits.hint" />
				</div>
				<Button size="sm" className="btn-red" onClick={() => showSentinelRateLimitModal("new")}>
					<T id="object.add" tData={{ object: "sentinel.rate-limit" }} />
				</Button>
			</div>
			{policies.length === 0 ? (
				<div className="card-body text-center text-secondary py-5">
					<T id="sentinel.rate-limits.empty" />
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
									<T id="sentinel.rate-limit.rate" />
								</th>
								<th>
									<T id="sentinel.rate-limit.hosts" />
								</th>
								<th>
									<T id="sentinel.rate-limit.refused" />
								</th>
								<th className="w-1" />
							</tr>
						</thead>
						<tbody>
							{policies.map((r) => (
								<tr key={r.id} className={cn(!r.enabled && "text-secondary")}>
									<td>
										<div className="fw-bold">{r.name}</div>
										{!r.enabled ? (
											<span className="badge bg-secondary-lt">
												<T id="disabled" />
											</span>
										) : r.dryRun ? (
											<span className="badge bg-yellow-lt">
												<T id="sentinel.rate-limit.dry-run" />
											</span>
										) : null}
									</td>
									<td className="text-nowrap">
										<T
											id="sentinel.rate-limit.summary"
											data={{ rps: r.requestsPerSecond, burst: r.burst }}
										/>
										{r.maxConnections ? (
											<div className="text-secondary small">
												<T
													id="sentinel.rate-limit.connections-summary"
													data={{ n: r.maxConnections }}
												/>
											</div>
										) : null}
									</td>
									<td style={{ maxWidth: 320 }}>
										<div className="text-truncate">
											{r.hostIds.length ? r.hostIds.map(hostName).join(", ") : "-"}
										</div>
									</td>
									<td className="text-nowrap">
										{r.dryRun ? (
											<T
												id="sentinel.rate-limit.would-limit"
												data={{ n: r.stats?.wouldLimit || 0 }}
											/>
										) : (
											r.stats?.limited || 0
										)}
									</td>
									<td className="text-nowrap">
										<button
											type="button"
											className="btn btn-sm btn-ghost-primary btn-icon"
											aria-label={intl.formatMessage({ id: "action.edit" })}
											onClick={() => showSentinelRateLimitModal(r.id)}
										>
											<IconEdit size={16} />
										</button>
										<button
											type="button"
											className="btn btn-sm btn-ghost-danger btn-icon"
											aria-label={intl.formatMessage({ id: "action.delete" })}
											onClick={() => remove(r)}
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
