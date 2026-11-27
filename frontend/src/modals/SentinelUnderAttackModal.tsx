import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import {
	type SentinelUnderAttackConfig,
	type SentinelUnderAttackHost,
	type SentinelUnderAttackMode,
	saveSentinelUnderAttack,
} from "src/api/backend";
import { Button } from "src/components";
import { useInvalidateSentinel } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";
import { SentinelChallengeFields } from "./SentinelChallengeFields";

const MODES: SentinelUnderAttackMode[] = ["off", "auto", "on"];

const showSentinelUnderAttackModal = (host: SentinelUnderAttackHost) => {
	EasyModal.show(SentinelUnderAttackModal, { host });
};

interface Props extends InnerModalProps {
	host: SentinelUnderAttackHost;
}

const SentinelUnderAttackModal = EasyModal.create(({ host, visible, remove }: Props) => {
	const invalidate = useInvalidateSentinel();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [mode, setMode] = useState<SentinelUnderAttackMode>(host.underAttack);
	const [config, setConfig] = useState<SentinelUnderAttackConfig>(host.config);
	const set = (p: Partial<SentinelUnderAttackConfig>) => setConfig((c) => ({ ...c, ...p }));

	const onSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		if (isSubmitting) return;
		setIsSubmitting(true);
		setErrorMsg(null);
		try {
			await saveSentinelUnderAttack(host.proxyHostId, mode, config);
			showObjectSuccess("sentinel.under-attack", "saved");
			remove();
		} catch (err: any) {
			setErrorMsg(err.message);
		}
		invalidate();
		setIsSubmitting(false);
	};

	const num = (id: string, label: string, key: keyof SentinelUnderAttackConfig, min: number, max: number) => (
		<div className="col-md-3 mb-3">
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
				disabled={mode !== "auto"}
				value={config[key] as number}
				onChange={(e) => set({ [key]: Number(e.target.value) })}
			/>
		</div>
	);

	return (
		<Modal show={visible} onHide={isSubmitting ? undefined : remove} size="lg">
			<form onSubmit={onSubmit}>
				<Modal.Header closeButton>
					<Modal.Title>
						<T id="sentinel.under-attack" />
						<span className="text-secondary fw-normal ms-2">{host.domainNames[0]}</span>
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
						{errorMsg}
					</Alert>
					<div className="mb-3">
						<div className="form-selectgroup">
							{MODES.map((m) => (
								<label key={m} className="form-selectgroup-item">
									<input
										type="radio"
										name="ua-mode"
										value={m}
										className="form-selectgroup-input"
										checked={mode === m}
										onChange={() => setMode(m)}
									/>
									<span className="form-selectgroup-label">
										<T id={`sentinel.under-attack.mode.${m}`} />
									</span>
								</label>
							))}
						</div>
						<div className="form-hint mt-2">
							<T id={`sentinel.under-attack.mode.${mode}.hint`} />
						</div>
					</div>
					<h4 className="mt-4">
						<T id="sentinel.under-attack.challenge" />
					</h4>
					<SentinelChallengeFields idPrefix="ua-ch" value={config} onChange={(v) => set(v)} />
					<h4 className="mt-2">
						<T id="sentinel.under-attack.thresholds" />
					</h4>
					<div className="row">
						{num("ua-rps", "sentinel.under-attack.rps", "rps", 1, 1000000)}
						{num("ua-pct", "sentinel.under-attack.blocked-pct", "blockedPct", 0, 100)}
						{num("ua-window", "sentinel.under-attack.window", "windowS", 10, 600)}
						{num("ua-duration", "sentinel.under-attack.duration", "durationS", 60, 86400)}
					</div>
					<div className="form-hint">
						<T id="sentinel.under-attack.thresholds.hint" />
					</div>
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
						{intl.formatMessage({ id: "save" })}
					</Button>
				</Modal.Footer>
			</form>
		</Modal>
	);
});

export { showSentinelUnderAttackModal };
