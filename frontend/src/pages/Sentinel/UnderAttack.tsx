import { IconBell, IconEdit, IconPlayerStop } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { deactivateSentinelUnderAttack, type SentinelUnderAttackHost } from "src/api/backend";
import { Button, LoadingPage } from "src/components";
import { useInvalidateSentinel, useSentinelUnderAttack, useSentinelUnderAttackEvents } from "src/hooks";
import { formatDateTime, getLocale, intl, T } from "src/locale";
import { showSentinelAlertsModal, showSentinelUnderAttackModal } from "src/modals";
import { showError, showSuccess } from "src/notifications";

function State({ h }: { h: SentinelUnderAttackHost }) {
	if (!h.enabled) {
		return (
			<span className="badge bg-secondary-lt">
				<T id="disabled" />
			</span>
		);
	}
	if (h.active) {
		return (
			<>
				<span className="badge bg-red text-red-fg">
					<T id="sentinel.under-attack.state.active" />
				</span>
				{h.since ? (
					<div className="text-secondary small mt-1">
						<T
							id="sentinel.under-attack.state.since"
							data={{ date: formatDateTime(h.since, getLocale()) }}
						/>
					</div>
				) : null}
				{h.reason ? <div className="text-secondary small text-truncate">{h.reason}</div> : null}
			</>
		);
	}
	if (h.underAttack === "auto") {
		return (
			<span className="badge bg-green-lt">
				<T id="sentinel.under-attack.state.watching" />
			</span>
		);
	}
	return <span className="text-secondary">-</span>;
}

export default function UnderAttack() {
	const { data, isLoading, isError, error, isFetching } = useSentinelUnderAttack({ refetchInterval: 15 * 1000 });
	const events = useSentinelUnderAttackEvents({ refetchInterval: 30 * 1000 });
	const invalidate = useInvalidateSentinel();
	const [busy, setBusy] = useState<number | null>(null);

	if (isLoading) {
		return <LoadingPage noLogo />;
	}
	if (isError) {
		return <Alert variant="danger">{error?.message || "Unknown error"}</Alert>;
	}
	const hosts = data || [];

	const stop = async (h: SentinelUnderAttackHost) => {
		setBusy(h.proxyHostId);
		try {
			await deactivateSentinelUnderAttack(h.proxyHostId);
			showSuccess(intl.formatMessage({ id: "sentinel.under-attack.stopped" }));
		} catch (err: any) {
			showError(err.message);
		}
		invalidate();
		setBusy(null);
	};

	return (
		<>
			<div className="card-body border-bottom py-3 d-flex align-items-center flex-wrap gap-2">
				<div className="text-secondary small me-auto">
					<T id="sentinel.under-attack.hint" />
				</div>
				<Button size="sm" onClick={() => showSentinelAlertsModal()}>
					<IconBell size={16} className="me-1" />
					<T id="sentinel.alerts" />
				</Button>
			</div>
			{hosts.length === 0 ? (
				<div className="card-body text-center text-secondary py-5">
					<T id="sentinel.rule.no-hosts" />
				</div>
			) : (
				<div className={cn("table-responsive", isFetching && "opacity-75")}>
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="column.source" />
								</th>
								<th>
									<T id="sentinel.host-protection" />
								</th>
								<th>
									<T id="column.status" />
								</th>
								<th className="w-1" />
							</tr>
						</thead>
						<tbody>
							{hosts.map((h) => (
								<tr key={h.proxyHostId}>
									<td>
										<div className="fw-bold">{h.domainNames[0]}</div>
										{h.domainNames.length > 1 ? (
											<div className="text-secondary small">
												{h.domainNames.slice(1).join(", ")}
											</div>
										) : null}
									</td>
									<td>
										<T id={`sentinel.under-attack.mode.${h.underAttack}`} />
										{h.underAttack === "auto" ? (
											<div className="text-secondary small">
												<T
													id="sentinel.under-attack.auto-summary"
													data={{ rps: h.config.rps, pct: h.config.blockedPct }}
												/>
											</div>
										) : null}
										<div className="d-flex flex-wrap gap-1 mt-1">
											{h.config.pages ? (
												<span className="badge bg-blue-lt">
													<T id="sentinel.badge.pages" />
												</span>
											) : null}
											{h.noAutoban ? (
												<span className="badge bg-secondary-lt">
													<T id="sentinel.badge.no-autoban" />
												</span>
											) : null}
											{h.rateLimit ? (
												<span className="badge bg-yellow-lt">{h.rateLimit.name}</span>
											) : null}
										</div>
									</td>
									<td style={{ maxWidth: 360 }}>
										<State h={h} />
									</td>
									<td className="text-nowrap">
										{h.active && h.underAttack === "auto" ? (
											<button
												type="button"
												className="btn btn-sm btn-ghost-danger btn-icon"
												disabled={busy !== null}
												aria-label={intl.formatMessage({ id: "sentinel.under-attack.stop" })}
												title={intl.formatMessage({ id: "sentinel.under-attack.stop" })}
												onClick={() => stop(h)}
											>
												<IconPlayerStop size={16} />
											</button>
										) : null}
										<button
											type="button"
											className="btn btn-sm btn-ghost-primary btn-icon"
											aria-label={intl.formatMessage({ id: "action.edit" })}
											onClick={() => showSentinelUnderAttackModal(h)}
										>
											<IconEdit size={16} />
										</button>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
			{events.data?.length ? (
				<div className="card-body border-top">
					<h4>
						<T id="sentinel.under-attack.events" />
					</h4>
					<ul className="list-unstyled small mb-0">
						{events.data.slice(0, 10).map((e) => (
							<li key={`${e.at}-${e.id}-${e.on}`} className="mb-1">
								<span className="text-secondary me-2">{formatDateTime(e.at, getLocale())}</span>
								<span className={cn("badge me-2", e.on ? "bg-red-lt" : "bg-green-lt")}>
									<T
										id={
											e.on
												? "sentinel.under-attack.event.on"
												: e.manual
													? "sentinel.under-attack.event.stopped"
													: "sentinel.under-attack.event.off"
										}
									/>
								</span>
								<span className="fw-bold me-2">{e.host}</span>
								{e.on ? <span className="text-secondary">{e.reason}</span> : null}
							</li>
						))}
					</ul>
				</div>
			) : null}
		</>
	);
}
