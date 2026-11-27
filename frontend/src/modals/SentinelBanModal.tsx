import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { createSentinelBan } from "src/api/backend";
import { Button } from "src/components";
import { useInvalidateSentinel } from "src/hooks";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";

// Ban lengths offered (seconds, 0 = permanent)
const DURATIONS = [3600, 86400, 7 * 86400, 30 * 86400, 0];

const durationLabel = (s: number) =>
	s === 0
		? intl.formatMessage({ id: "sentinel.ban.permanent" })
		: s < 86400
			? intl.formatMessage({ id: "sentinel.duration.hours" }, { n: s / 3600 })
			: intl.formatMessage({ id: "sentinel.duration.days" }, { n: s / 86400 });

const showSentinelBanModal = () => {
	EasyModal.show(SentinelBanModal);
};

const SentinelBanModal = EasyModal.create(({ visible, remove }: InnerModalProps) => {
	const invalidate = useInvalidateSentinel();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [busy, setBusy] = useState(false);
	const [ip, setIp] = useState("");
	const [reason, setReason] = useState("");
	const [duration, setDuration] = useState(86400);

	const onSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		if (busy) return;
		setBusy(true);
		setErrorMsg(null);
		try {
			const ban = await createSentinelBan(ip.trim(), reason, duration);
			showSuccess(intl.formatMessage({ id: "sentinel.ban.created" }, { ip: ban.ip }));
			invalidate();
			remove();
		} catch (err: any) {
			setErrorMsg(err.message);
		}
		setBusy(false);
	};

	return (
		<Modal show={visible} onHide={busy ? undefined : remove}>
			<form onSubmit={onSubmit}>
				<Modal.Header closeButton>
					<Modal.Title>
						<T id="sentinel.ban.add" />
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
						{errorMsg}
					</Alert>
					<div className="mb-3">
						<label htmlFor="sb-ip" className="form-label required">
							<T id="sentinel.ban.ip" />
						</label>
						<input
							id="sb-ip"
							className="form-control"
							required
							maxLength={64}
							placeholder="203.0.113.7"
							value={ip}
							onChange={(e) => setIp(e.target.value)}
						/>
						<div className="form-hint">
							<T id="sentinel.ban.ip.hint" />
						</div>
					</div>
					<div className="mb-3">
						<label htmlFor="sb-reason" className="form-label">
							<T id="sentinel.ban.reason" />
						</label>
						<input
							id="sb-reason"
							className="form-control"
							maxLength={500}
							value={reason}
							onChange={(e) => setReason(e.target.value)}
						/>
					</div>
					<div className="mb-0">
						<label htmlFor="sb-duration" className="form-label">
							<T id="sentinel.ban.duration" />
						</label>
						<select
							id="sb-duration"
							className="form-select"
							value={duration}
							onChange={(e) => setDuration(Number(e.target.value))}
						>
							{DURATIONS.map((d) => (
								<option key={d} value={d}>
									{durationLabel(d)}
								</option>
							))}
						</select>
					</div>
				</Modal.Body>
				<Modal.Footer>
					<Button onClick={remove} disabled={busy}>
						<T id="cancel" />
					</Button>
					<Button
						type="submit"
						actionType="primary"
						className="ms-auto bg-red"
						isLoading={busy}
						disabled={busy}
					>
						{intl.formatMessage({ id: "sentinel.ban.submit" })}
					</Button>
				</Modal.Footer>
			</form>
		</Modal>
	);
});

export { showSentinelBanModal };
