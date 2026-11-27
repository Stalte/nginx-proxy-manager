import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { type SentinelAutoban, saveSentinelAutoban } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useInvalidateSentinel, useSentinelAutoban } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";

const showSentinelAutobanModal = () => {
	EasyModal.show(SentinelAutobanModal);
};

const splitLines = (s: string) =>
	s
		.split(/[\s,]+/)
		.map((x) => x.trim())
		.filter(Boolean);

const SentinelAutobanModal = EasyModal.create(({ visible, remove }: InnerModalProps) => {
	const { data, isLoading } = useSentinelAutoban();
	if (isLoading || !data) {
		return (
			<Modal show={visible} onHide={remove}>
				<Loading noLogo />
			</Modal>
		);
	}
	return <AutobanForm initial={data} visible={visible} remove={remove} />;
});

interface FormProps {
	initial: SentinelAutoban;
	visible: boolean;
	remove: () => void;
}

function AutobanForm({ initial, visible, remove }: FormProps) {
	const invalidate = useInvalidateSentinel();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [busy, setBusy] = useState(false);
	const [form, setForm] = useState<SentinelAutoban>(initial);
	const [codes, setCodes] = useState(initial.badBehaviourCodes.join(", "));
	const [exempt, setExempt] = useState(initial.exempt.join("\n"));
	const set = (p: Partial<SentinelAutoban>) => setForm((f) => ({ ...f, ...p }));

	const onSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		if (busy) return;
		setBusy(true);
		setErrorMsg(null);
		try {
			await saveSentinelAutoban({
				...form,
				badBehaviourCodes: splitLines(codes).map(Number),
				exempt: splitLines(exempt),
			});
			showObjectSuccess("sentinel.autoban", "saved");
			invalidate();
			remove();
		} catch (err: any) {
			setErrorMsg(err.message);
		}
		setBusy(false);
	};

	const num = (id: string, label: string, key: keyof SentinelAutoban, min: number, max: number, off = false) => (
		<div className="col-md-4 mb-3">
			<label htmlFor={id} className="form-label">
				<T id={label} />
			</label>
			<input
				id={id}
				type="number"
				className="form-control"
				min={min}
				max={max}
				required
				disabled={off}
				value={form[key] as number}
				onChange={(e) => set({ [key]: Number(e.target.value) })}
			/>
		</div>
	);

	const toggle = (key: "enabled" | "detections" | "badBehaviour", label: string) => (
		<label className="form-check form-switch mb-2">
			<input
				type="checkbox"
				className="form-check-input"
				checked={form[key]}
				onChange={(e) => set({ [key]: e.target.checked })}
			/>
			<span className="form-check-label">
				<T id={label} />
			</span>
		</label>
	);

	return (
		<Modal show={visible} onHide={busy ? undefined : remove} size="lg">
			<form onSubmit={onSubmit}>
				<Modal.Header closeButton>
					<Modal.Title>
						<T id="sentinel.autoban" />
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
						{errorMsg}
					</Alert>
					{toggle("enabled", "sentinel.autoban.enabled")}
					<div className="form-hint mb-3">
						<T id="sentinel.autoban.hint" />
					</div>

					<h4 className="mt-3">
						<T id="sentinel.autoban.bad-behaviour" />
					</h4>
					{toggle("badBehaviour", "sentinel.autoban.bad-behaviour.enabled")}
					<div className="row">
						<div className="col-md-4 mb-3">
							<label htmlFor="ab-codes" className="form-label">
								<T id="sentinel.autoban.codes" />
							</label>
							<input
								id="ab-codes"
								className="form-control"
								disabled={!form.badBehaviour}
								value={codes}
								onChange={(e) => setCodes(e.target.value)}
							/>
						</div>
						{num(
							"ab-bb-threshold",
							"sentinel.autoban.threshold",
							"badBehaviourThreshold",
							3,
							100000,
							!form.badBehaviour,
						)}
						{num(
							"ab-bb-window",
							"sentinel.autoban.window",
							"badBehaviourWindowS",
							10,
							3600,
							!form.badBehaviour,
						)}
					</div>
					<div className="form-hint mb-3">
						<T id="sentinel.autoban.bad-behaviour.hint" />
					</div>

					<h4 className="mt-3">
						<T id="sentinel.autoban.detections" />
					</h4>
					{toggle("detections", "sentinel.autoban.detections.enabled")}
					<div className="row">
						{num("ab-threshold", "sentinel.autoban.threshold", "threshold", 3, 100000, !form.detections)}
						{num("ab-window", "sentinel.autoban.window", "windowS", 60, 86400, !form.detections)}
					</div>

					<h4 className="mt-3">
						<T id="sentinel.autoban.escalation" />
					</h4>
					<div className="row">
						{num("ab-duration", "sentinel.autoban.duration", "durationS", 60, 2592000)}
						{num("ab-max", "sentinel.autoban.max-duration", "maxDurationS", 60, 2592000)}
						{num("ab-permanent", "sentinel.autoban.permanent-after", "permanentAfter", 0, 100)}
					</div>
					<div className="form-hint mb-3">
						<T id="sentinel.autoban.escalation.hint" />
					</div>

					<label htmlFor="ab-exempt" className="form-label">
						<T id="sentinel.autoban.exempt" />
					</label>
					<textarea
						id="ab-exempt"
						className="form-control font-monospace"
						rows={3}
						placeholder={"192.168.0.0/16\n10.0.0.0/8"}
						value={exempt}
						onChange={(e) => setExempt(e.target.value)}
					/>
					<div className="form-hint">
						<T id="sentinel.autoban.exempt.hint" />
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
						{intl.formatMessage({ id: "save" })}
					</Button>
				</Modal.Footer>
			</form>
		</Modal>
	);
}

export { showSentinelAutobanModal };
