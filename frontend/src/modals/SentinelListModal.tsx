import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useEffect, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import type { SentinelList, SentinelListKind } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useSentinelList, useSetSentinelList } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";

export interface SentinelListPreset {
	name: string;
	kind: SentinelListKind;
	sourceUrl: string;
	description: string;
}

/** Presets only fill in the form; nothing is downloaded until the list is saved. */
export const SENTINEL_LIST_PRESETS: { id: string; kind: SentinelListKind; sourceUrl: string }[] = [
	{ id: "tor", kind: "ip", sourceUrl: "https://check.torproject.org/torbulkexitlist" },
	{
		id: "bad-bots",
		kind: "user_agent",
		sourceUrl:
			"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list",
	},
];

export const sentinelPreset = (id: string): SentinelListPreset | undefined => {
	const p = SENTINEL_LIST_PRESETS.find((x) => x.id === id);
	if (!p) return undefined;
	return {
		name: intl.formatMessage({ id: `sentinel.preset.${p.id}` }),
		description: intl.formatMessage({ id: `sentinel.preset.${p.id}.description` }),
		kind: p.kind,
		sourceUrl: p.sourceUrl,
	};
};

const REFRESH = [300, 900, 3600, 6 * 3600, 12 * 3600, 86400, 7 * 86400];

const refreshLabel = (s: number) => {
	if (s % 86400 === 0) return intl.formatMessage({ id: "sentinel.every-days" }, { n: s / 86400 });
	if (s % 3600 === 0) return intl.formatMessage({ id: "sentinel.every-hours" }, { n: s / 3600 });
	return intl.formatMessage({ id: "sentinel.every-minutes" }, { n: Math.round(s / 60) });
};

const showSentinelListModal = (id: number | "new", preset?: SentinelListPreset) => {
	EasyModal.show(SentinelListModal, { listId: id, preset });
};

interface Props extends InnerModalProps {
	listId: number | "new";
	preset?: SentinelListPreset;
}

const SentinelListModal = EasyModal.create(({ listId: id, preset, visible, remove }: Props) => {
	const { data, isLoading, error } = useSentinelList(id);
	const { mutate: setList } = useSetSentinelList();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [form, setForm] = useState({
		name: preset?.name || "",
		description: preset?.description || "",
		kind: (preset?.kind || "ip") as SentinelListKind,
		source: preset ? "url" : "manual",
		sourceUrl: preset?.sourceUrl || "",
		refreshS: 3600,
		text: "",
	});

	useEffect(() => {
		if (data) {
			setForm({
				name: data.name,
				description: data.description,
				kind: data.kind,
				source: data.sourceUrl ? "url" : "manual",
				sourceUrl: data.sourceUrl,
				refreshS: data.refreshS || 3600,
				text: (data.items || []).join("\n"),
			});
		}
	}, [data]);

	const set = (p: Partial<typeof form>) => setForm((f) => ({ ...f, ...p }));
	const isFeed = form.source === "url";
	const isEdit = id !== "new";
	const refreshOptions = REFRESH.includes(form.refreshS)
		? REFRESH
		: [...REFRESH, form.refreshS].sort((a, b) => a - b);

	const onSubmit = (e: React.FormEvent) => {
		e.preventDefault();
		if (isSubmitting) return;
		setIsSubmitting(true);
		setErrorMsg(null);
		const items = [
			...new Set(
				form.text
					.split(/\r?\n/)
					.map((s) => s.trim())
					.filter(Boolean),
			),
		];
		const payload: Partial<SentinelList> = {
			id: isEdit ? (id as number) : undefined,
			name: form.name.trim(),
			description: form.description.trim(),
			kind: form.kind,
			sourceUrl: isFeed ? form.sourceUrl.trim() : "",
			refreshS: form.refreshS,
			items: isFeed ? [] : items,
		};
		setList(payload, {
			onError: (err: any) => setErrorMsg(err.message),
			onSuccess: () => {
				showObjectSuccess("sentinel.list", "saved");
				remove();
			},
			onSettled: () => setIsSubmitting(false),
		});
	};

	if (isLoading || (error && !data)) {
		return (
			<Modal show={visible} onHide={remove}>
				{error && (
					<Alert variant="danger" className="m-3">
						{error.message}
					</Alert>
				)}
				{isLoading && <Loading noLogo />}
			</Modal>
		);
	}

	return (
		<Modal show={visible} onHide={isSubmitting ? undefined : remove} size="lg">
			<form onSubmit={onSubmit}>
				<Modal.Header closeButton>
					<Modal.Title>
						<T id={isEdit ? "object.edit" : "object.add"} tData={{ object: "sentinel.list" }} />
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
						{errorMsg}
					</Alert>
					<div className="row">
						<div className="col-md-8 mb-3">
							<label htmlFor="sl-name" className="form-label required">
								<T id="column.name" />
							</label>
							<input
								id="sl-name"
								className="form-control"
								required
								maxLength={64}
								value={form.name}
								onChange={(e) => set({ name: e.target.value })}
							/>
						</div>
						<div className="col-md-4 mb-3">
							<label htmlFor="sl-kind" className="form-label">
								<T id="sentinel.list.kind" />
							</label>
							<select
								id="sl-kind"
								className="form-select"
								value={form.kind}
								disabled={isEdit}
								onChange={(e) => set({ kind: e.target.value as SentinelListKind })}
							>
								<option value="ip">{intl.formatMessage({ id: "sentinel.list.kind.ip" })}</option>
								<option value="user_agent">
									{intl.formatMessage({ id: "sentinel.list.kind.user_agent" })}
								</option>
							</select>
						</div>
					</div>
					<div className="mb-3">
						<label htmlFor="sl-desc" className="form-label">
							<T id="sentinel.description" />
						</label>
						<input
							id="sl-desc"
							className="form-control"
							maxLength={500}
							value={form.description}
							onChange={(e) => set({ description: e.target.value })}
						/>
					</div>
					<div className="mb-3">
						<div className="form-label">
							<T id="sentinel.list.source" />
						</div>
						<div className="btn-group w-100" role="group">
							<input
								type="radio"
								className="btn-check"
								id="sl-src-manual"
								checked={!isFeed}
								onChange={() => set({ source: "manual" })}
							/>
							<label htmlFor="sl-src-manual" className="btn">
								<T id="sentinel.list.source.manual" />
							</label>
							<input
								type="radio"
								className="btn-check"
								id="sl-src-url"
								checked={isFeed}
								onChange={() => set({ source: "url" })}
							/>
							<label htmlFor="sl-src-url" className="btn">
								<T id="sentinel.list.source.url" />
							</label>
						</div>
					</div>
					{isFeed ? (
						<div className="row">
							<div className="col-md-8 mb-3">
								<label htmlFor="sl-url" className="form-label required">
									<T id="sentinel.list.url" />
								</label>
								<input
									id="sl-url"
									type="url"
									required
									className="form-control font-monospace"
									placeholder="https://example.com/blocklist.txt"
									maxLength={2048}
									value={form.sourceUrl}
									onChange={(e) => set({ sourceUrl: e.target.value })}
								/>
								<small className="form-hint">
									<T id="sentinel.list.url.hint" />
								</small>
							</div>
							<div className="col-md-4 mb-3">
								<label htmlFor="sl-refresh" className="form-label">
									<T id="sentinel.list.refresh" />
								</label>
								<select
									id="sl-refresh"
									className="form-select"
									value={form.refreshS}
									onChange={(e) => set({ refreshS: Number(e.target.value) })}
								>
									{refreshOptions.map((s) => (
										<option key={s} value={s}>
											{refreshLabel(s)}
										</option>
									))}
								</select>
							</div>
						</div>
					) : (
						<div className="mb-3">
							<label htmlFor="sl-items" className="form-label">
								<T id="sentinel.list.entries" />
							</label>
							<textarea
								id="sl-items"
								className="form-control font-monospace"
								rows={10}
								placeholder={
									form.kind === "ip" ? "203.0.113.7\n198.51.100.0/24\n2001:db8::/32" : "sqlmap\nnikto"
								}
								value={form.text}
								onChange={(e) => set({ text: e.target.value })}
							/>
							<small className="form-hint">
								<T
									id={
										form.kind === "ip"
											? "sentinel.list.entries.ip-hint"
											: "sentinel.list.entries.ua-hint"
									}
								/>
							</small>
						</div>
					)}
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
						<T id="save" />
					</Button>
				</Modal.Footer>
			</form>
		</Modal>
	);
});

export { showSentinelListModal };
