import { IconBan, IconLockOpen, IconSettings } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { liftSentinelBan, type SentinelBan } from "src/api/backend";
import { Button, LoadingPage } from "src/components";
import { useInvalidateSentinel, useSentinelAutoban, useSentinelBans } from "src/hooks";
import { formatDateTime, getLocale, intl, T } from "src/locale";
import { showSentinelAutobanModal, showSentinelBanModal } from "src/modals";
import { showError, showSuccess } from "src/notifications";

function Until({ b }: { b: SentinelBan }) {
	if (!b.active) {
		return (
			<span className="text-secondary">
				<T id="sentinel.ban.ended" />
			</span>
		);
	}
	if (b.expiresAt === null) {
		return (
			<span className="badge bg-red-lt">
				<T id="sentinel.ban.permanent" />
			</span>
		);
	}
	return <span>{formatDateTime(new Date(b.expiresAt * 1000).toISOString(), getLocale())}</span>;
}

export default function Bans() {
	const { data, isLoading, isError, error, isFetching } = useSentinelBans({ refetchInterval: 15 * 1000 });
	const settings = useSentinelAutoban();
	const invalidate = useInvalidateSentinel();
	const [busy, setBusy] = useState<number | null>(null);
	const [showEnded, setShowEnded] = useState(false);

	if (isLoading) {
		return <LoadingPage noLogo />;
	}
	if (isError) {
		return <Alert variant="danger">{error?.message || "Unknown error"}</Alert>;
	}
	const all = data || [];
	const bans = showEnded ? all : all.filter((b) => b.active);
	const ended = all.length - all.filter((b) => b.active).length;

	const lift = async (b: SentinelBan) => {
		setBusy(b.id);
		try {
			await liftSentinelBan(b.id);
			showSuccess(intl.formatMessage({ id: "sentinel.ban.lifted" }, { ip: b.ip }));
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
					{settings.data?.enabled ? (
						<span className="badge bg-green-lt me-2">
							<T id="sentinel.autoban.on" />
						</span>
					) : (
						<span className="badge bg-secondary-lt me-2">
							<T id="sentinel.autoban.off" />
						</span>
					)}
					<T id="sentinel.bans.hint" />
				</div>
				<Button size="sm" onClick={() => showSentinelAutobanModal()}>
					<IconSettings size={16} className="me-1" />
					<T id="sentinel.autoban" />
				</Button>
				<Button size="sm" className="btn-red" onClick={() => showSentinelBanModal()}>
					<IconBan size={16} className="me-1" />
					<T id="sentinel.ban.add" />
				</Button>
			</div>
			{bans.length === 0 ? (
				<div className="card-body text-center text-secondary py-5">
					<T id="sentinel.bans.empty" />
				</div>
			) : (
				<div className={cn("table-responsive", isFetching && "opacity-75")}>
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="sentinel.ban.ip" />
								</th>
								<th>
									<T id="sentinel.ban.reason" />
								</th>
								<th>
									<T id="sentinel.ban.offenses" />
								</th>
								<th>
									<T id="sentinel.ban.until" />
								</th>
								<th className="w-1" />
							</tr>
						</thead>
						<tbody>
							{bans.map((b) => (
								<tr key={b.id} className={cn(!b.active && "text-secondary")}>
									<td className="text-nowrap">
										<code>{b.ip}</code>
										<div className="small">
											<span
												className={cn(
													"badge",
													b.source === "auto" ? "bg-orange-lt" : "bg-blue-lt",
												)}
											>
												<T id={`sentinel.ban.source.${b.source}`} />
											</span>
										</div>
									</td>
									<td style={{ maxWidth: 420 }}>
										<div className="text-truncate" title={b.reason}>
											{b.reason}
										</div>
										<div className="text-secondary small">
											{formatDateTime(b.modifiedOn, getLocale())}
										</div>
									</td>
									<td>{b.offenses || "-"}</td>
									<td className="text-nowrap">
										<Until b={b} />
									</td>
									<td className="text-nowrap">
										{b.active ? (
											<button
												type="button"
												className="btn btn-sm btn-ghost-success btn-icon"
												disabled={busy !== null}
												aria-label={intl.formatMessage({ id: "sentinel.ban.lift" })}
												title={intl.formatMessage({ id: "sentinel.ban.lift" })}
												onClick={() => lift(b)}
											>
												<IconLockOpen size={16} />
											</button>
										) : null}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
			{ended ? (
				<div className="card-body border-top py-2">
					<label className="form-check mb-0 small">
						<input
							type="checkbox"
							className="form-check-input"
							checked={showEnded}
							onChange={(e) => setShowEnded(e.target.checked)}
						/>
						<span className="form-check-label">
							<T id="sentinel.bans.show-ended" data={{ n: ended }} />
						</span>
					</label>
				</div>
			) : null}
		</>
	);
}
