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

// Presets for apps whose own clients (TV, mobile and desktop apps, API calls) cannot solve
// a browser challenge: only page loads are challenged, and Plex is left out of automatic
// bans because its apps routinely get 401/404 responses (expired tokens, missing artwork).
const PRESETS = {
	plex: {
		mode: "auto" as SentinelUnderAttackMode,
		noAutoban: true,
		config: { mode: "js", pages: true, rps: 500, blockedPct: 50, windowS: 60, durationS: 900 },
	},
	seerr: {
		mode: "auto" as SentinelUnderAttackMode,
		noAutoban: false,
		config: { mode: "js", pages: true, rps: 100, blockedPct: 50, windowS: 30, durationS: 900 },
	},
} as const;

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
	const [noAutoban, setNoAutoban] = useState(host.noAutoban);
	const set = (p: Partial<SentinelUnderAttackConfig>) => setConfig((c) => ({ ...c, ...p }));
	const applyPreset = (name: keyof typeof PRESETS) => {
		const p = PRESETS[name];
		setMode(p.mode);
		setNoAutoban(p.noAutoban);
		set(p.config);
	};

	const onSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		if (isSubmitting) return;
		setIsSubmitting(true);
		setErrorMsg(null);
		try {
			await saveSentinelUnderAttack(host.proxyHostId, mode, config, noAutoban);
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
						<T id="sentinel.host-protection" />
						<span className="text-secondary fw-normal ms-2">{host.domainNames[0]}</span>
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
						{errorMsg}
					</Alert>
					<div className="d-flex align-items-center flex-wrap gap-2 mb-3">
						<span className="text-secondary small me-1">
							<T id="sentinel.preset" />
						</span>
						<Button size="sm" onClick={() => applyPreset("plex")}>
							<T id="sentinel.preset.plex" />
						</Button>
						<Button size="sm" onClick={() => applyPreset("seerr")}>
							<T id="sentinel.preset.seerr" />
						</Button>
					</div>
					<div className="form-hint mb-3">
						<T id="sentinel.preset.hint" />
					</div>
					<h4>
						<T id="sentinel.under-attack" />
					</h4>
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
					<h4 className="mt-4">
						<T id="sentinel.bans" />
					</h4>
					<label className="form-check form-switch mb-0">
						<input
							type="checkbox"
							className="form-check-input"
							checked={noAutoban}
							onChange={(e) => setNoAutoban(e.target.checked)}
						/>
						<span className="form-check-label">
							<T id="sentinel.host.no-autoban" />
						</span>
					</label>
					<div className="form-hint">
						<T id="sentinel.host.no-autoban.hint" />
					</div>
					<div className="form-hint mt-2">
						{host.rateLimit ? (
							<T id="sentinel.host.rate-limit" data={{ name: host.rateLimit.name }} />
						) : (
							<T id="sentinel.host.rate-limit.none" />
						)}
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
