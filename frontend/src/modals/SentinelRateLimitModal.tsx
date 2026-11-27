import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { type SentinelRateLimit, saveSentinelRateLimit } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useInvalidateSentinel, useProxyHosts, useSentinelRateLimits } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";

const STATUS_CODES = [429, 503, 403];

const NEW_POLICY: Partial<SentinelRateLimit> = {
	name: "",
	enabled: true,
	requestsPerSecond: 10,
	burst: 20,
	maxConnections: 0,
	statusCode: 429,
	dryRun: true,
	exempt: [],
	hostIds: [],
};

const showSentinelRateLimitModal = (id: number | "new") => {
	EasyModal.show(SentinelRateLimitModal, { policyId: id });
};

interface Props extends InnerModalProps {
	policyId: number | "new";
}

const SentinelRateLimitModal = EasyModal.create(({ policyId, visible, remove }: Props) => {
	const policies = useSentinelRateLimits();
	const hosts = useProxyHosts();
	if (policies.isLoading || hosts.isLoading) {
		return (
			<Modal show={visible} onHide={remove}>
				<Loading noLogo />
			</Modal>
		);
	}
	const policy = policyId === "new" ? NEW_POLICY : policies.data?.find((p) => p.id === policyId) || NEW_POLICY;
	// hosts that another enabled policy already limits
	const taken = new Map<number, string>();
	for (const p of policies.data || []) {
		if (p.id === policy.id || !p.enabled) continue;
		for (const h of p.hostIds) taken.set(h, p.name);
	}
	return (
		<PolicyForm
			policy={policy}
			hosts={(hosts.data || []).map((h) => ({ id: h.id, name: h.domainNames.join(", ") }))}
			taken={taken}
			visible={visible}
			remove={remove}
		/>
	);
});

interface FormProps {
	policy: Partial<SentinelRateLimit>;
	hosts: { id: number; name: string }[];
	taken: Map<number, string>;
	visible: boolean;
	remove: () => void;
}

function PolicyForm({ policy, hosts, taken, visible, remove }: FormProps) {
	const invalidate = useInvalidateSentinel();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [busy, setBusy] = useState(false);
	const [form, setForm] = useState<Partial<SentinelRateLimit>>(policy);
	const [exempt, setExempt] = useState((policy.exempt || []).join("\n"));
	const set = (p: Partial<SentinelRateLimit>) => setForm((f) => ({ ...f, ...p }));
	const hostIds = form.hostIds || [];

	const onSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		if (busy) return;
		setBusy(true);
		setErrorMsg(null);
		try {
			await saveSentinelRateLimit({
				...form,
				exempt: exempt
					.split(/[\s,]+/)
					.map((x) => x.trim())
					.filter(Boolean),
			});
			showObjectSuccess("sentinel.rate-limit", "saved");
			invalidate();
			remove();
		} catch (err: any) {
			setErrorMsg(err.message);
		}
		setBusy(false);
	};

	const num = (id: string, label: string, key: keyof SentinelRateLimit, min: number, max: number) => (
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
				value={form[key] as number}
				onChange={(e) => set({ [key]: Number(e.target.value) })}
			/>
		</div>
	);

	return (
		<Modal show={visible} onHide={busy ? undefined : remove} size="lg">
			<form onSubmit={onSubmit}>
				<Modal.Header closeButton>
					<Modal.Title>
						<T id={form.id ? "object.edit" : "object.add"} tData={{ object: "sentinel.rate-limit" }} />
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
						{errorMsg}
					</Alert>
					<div className="mb-3">
						<label htmlFor="rl-name" className="form-label required">
							<T id="column.name" />
						</label>
						<input
							id="rl-name"
							className="form-control"
							required
							maxLength={64}
							value={form.name}
							onChange={(e) => set({ name: e.target.value })}
						/>
					</div>
					<div className="row">
						{num("rl-rps", "sentinel.rate-limit.rps", "requestsPerSecond", 1, 100000)}
						{num("rl-burst", "sentinel.rate-limit.burst", "burst", 0, 100000)}
						{num("rl-conn", "sentinel.rate-limit.connections", "maxConnections", 0, 100000)}
					</div>
					<div className="form-hint mb-3">
						<T id="sentinel.rate-limit.rate.hint" />
					</div>
					<div className="row">
						<div className="col-md-4 mb-3">
							<label htmlFor="rl-status" className="form-label">
								<T id="sentinel.rule.status" />
							</label>
							<select
								id="rl-status"
								className="form-select"
								value={form.statusCode}
								onChange={(e) => set({ statusCode: Number(e.target.value) })}
							>
								{STATUS_CODES.map((c) => (
									<option key={c} value={c}>
										{c}
									</option>
								))}
							</select>
						</div>
						<div className="col-md-8 mb-3">
							<label className="form-check form-switch mt-md-4">
								<input
									type="checkbox"
									className="form-check-input"
									checked={form.dryRun === true}
									onChange={(e) => set({ dryRun: e.target.checked })}
								/>
								<span className="form-check-label">
									<T id="sentinel.rate-limit.dry-run" />
								</span>
							</label>
							<div className="form-hint">
								<T id="sentinel.rate-limit.dry-run.hint" />
							</div>
						</div>
					</div>
					<div className="mb-3">
						<span className="form-label">
							<T id="sentinel.rate-limit.hosts" />
						</span>
						<div className="border rounded p-2" style={{ maxHeight: 180, overflowY: "auto" }}>
							{hosts.length ? (
								hosts.map((h) => (
									<label key={h.id} className="form-check mb-1">
										<input
											type="checkbox"
											className="form-check-input"
											checked={hostIds.includes(h.id)}
											disabled={taken.has(h.id) && !hostIds.includes(h.id)}
											onChange={(e) =>
												set({
													hostIds: e.target.checked
														? [...hostIds, h.id]
														: hostIds.filter((x) => x !== h.id),
												})
											}
										/>
										<span className="form-check-label">
											{h.name}
											{taken.has(h.id) ? (
												<span className="text-secondary small ms-2">
													<T
														id="sentinel.rate-limit.taken"
														data={{ name: taken.get(h.id) }}
													/>
												</span>
											) : null}
										</span>
									</label>
								))
							) : (
								<span className="text-secondary small">
									<T id="sentinel.rule.no-hosts" />
								</span>
							)}
						</div>
					</div>
					<div className="mb-3">
						<label htmlFor="rl-exempt" className="form-label">
							<T id="sentinel.rate-limit.exempt" />
						</label>
						<textarea
							id="rl-exempt"
							className="form-control font-monospace"
							rows={2}
							placeholder={"192.168.0.0/16\n10.0.0.0/8"}
							value={exempt}
							onChange={(e) => setExempt(e.target.value)}
						/>
					</div>
					<label className="form-check form-switch mb-0">
						<input
							type="checkbox"
							className="form-check-input"
							checked={form.enabled !== false}
							onChange={(e) => set({ enabled: e.target.checked })}
						/>
						<span className="form-check-label">
							<T id="sentinel.rule.enabled" />
						</span>
					</label>
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

export { showSentinelRateLimitModal };
