import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useEffect, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { type SentinelAlerts, type SentinelAlertType, saveSentinelAlerts, testSentinelAlerts } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useInvalidateSentinel, useSentinelAlerts } from "src/hooks";
import { intl, T } from "src/locale";
import { showError, showObjectSuccess, showSuccess } from "src/notifications";

const TYPES: SentinelAlertType[] = ["discord", "slack", "ntfy", "gotify", "webhook"];
const WITH_TOKEN: SentinelAlertType[] = ["ntfy", "gotify", "webhook"];

const showSentinelAlertsModal = () => {
	EasyModal.show(SentinelAlertsModal);
};

const SentinelAlertsModal = EasyModal.create(({ visible, remove }: InnerModalProps) => {
	const { data, isLoading } = useSentinelAlerts();
	const invalidate = useInvalidateSentinel();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [busy, setBusy] = useState(false);
	const [form, setForm] = useState<SentinelAlerts>({ enabled: false, type: "discord", url: "", token: "" });
	const set = (p: Partial<SentinelAlerts>) => setForm((f) => ({ ...f, ...p }));

	useEffect(() => {
		if (data) {
			setForm({ enabled: data.enabled, type: data.type, url: data.url, token: "" });
		}
	}, [data]);

	const save = async () => {
		await saveSentinelAlerts(form);
		invalidate();
	};

	const onSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		if (busy) return;
		setBusy(true);
		setErrorMsg(null);
		try {
			await save();
			showObjectSuccess("sentinel.alerts", "saved");
			remove();
		} catch (err: any) {
			setErrorMsg(err.message);
		}
		setBusy(false);
	};

	const onTest = async () => {
		setBusy(true);
		setErrorMsg(null);
		try {
			await save();
			await testSentinelAlerts();
			showSuccess(intl.formatMessage({ id: "sentinel.alerts.test-sent" }));
		} catch (err: any) {
			showError(err.message);
		}
		setBusy(false);
	};

	return (
		<Modal show={visible} onHide={busy ? undefined : remove}>
			<form onSubmit={onSubmit}>
				<Modal.Header closeButton>
					<Modal.Title>
						<T id="sentinel.alerts" />
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					{isLoading ? (
						<Loading noLogo />
					) : (
						<>
							<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
								{errorMsg}
							</Alert>
							<p className="text-secondary">
								<T id="sentinel.alerts.hint" />
							</p>
							<label className="form-check form-switch mb-3">
								<input
									type="checkbox"
									className="form-check-input"
									checked={form.enabled}
									onChange={(e) => set({ enabled: e.target.checked })}
								/>
								<span className="form-check-label">
									<T id="sentinel.alerts.enabled" />
								</span>
							</label>
							<div className="mb-3">
								<label htmlFor="al-type" className="form-label">
									<T id="sentinel.alerts.type" />
								</label>
								<select
									id="al-type"
									className="form-select"
									value={form.type}
									onChange={(e) => set({ type: e.target.value as SentinelAlertType })}
								>
									{TYPES.map((t) => (
										<option key={t} value={t}>
											{intl.formatMessage({ id: `sentinel.alerts.type.${t}` })}
										</option>
									))}
								</select>
							</div>
							<div className="mb-3">
								<label htmlFor="al-url" className="form-label">
									<T id="sentinel.list.url" />
								</label>
								<input
									id="al-url"
									type="url"
									className="form-control font-monospace"
									maxLength={2048}
									required={form.enabled}
									value={form.url}
									placeholder={intl.formatMessage({ id: `sentinel.alerts.url.${form.type}` })}
									onChange={(e) => set({ url: e.target.value })}
								/>
							</div>
							{WITH_TOKEN.includes(form.type) ? (
								<div className="mb-3">
									<label htmlFor="al-token" className="form-label">
										<T id="sentinel.alerts.token" />
									</label>
									<input
										id="al-token"
										type="password"
										className="form-control"
										autoComplete="new-password"
										maxLength={256}
										value={form.token}
										placeholder={
											data?.hasToken
												? intl.formatMessage({ id: "sentinel.alerts.token.kept" })
												: ""
										}
										onChange={(e) => set({ token: e.target.value })}
									/>
								</div>
							) : null}
							{data?.last?.at && !data.last.ok ? (
								<div className="text-warning small">
									<T id="sentinel.alerts.last-failed" data={{ error: data.last.error }} />
								</div>
							) : null}
						</>
					)}
				</Modal.Body>
				<Modal.Footer>
					<Button onClick={remove} disabled={busy}>
						<T id="cancel" />
					</Button>
					<Button onClick={onTest} disabled={busy || !form.url} className="ms-auto">
						<T id="sentinel.alerts.test" />
					</Button>
					<Button type="submit" actionType="primary" className="bg-red" isLoading={busy} disabled={busy}>
						<T id="save" />
					</Button>
				</Modal.Footer>
			</form>
		</Modal>
	);
});

export { showSentinelAlertsModal };
