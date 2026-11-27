import type { SentinelChallenge } from "src/api/backend";
import { intl, T } from "src/locale";

export const DEFAULT_CHALLENGE: SentinelChallenge = {
	mode: "js",
	difficulty: 16,
	ttl: 86400,
	bind: "ip",
	pages: false,
};

// Pass lifetimes offered (seconds)
const TTLS = [300, 900, 3600, 6 * 3600, 86400, 7 * 86400];
// Proof-of-work difficulty (bits): about 2^bits hashes in the browser
const BITS = [12, 14, 16, 18, 20, 22, 24];

const ttlLabel = (s: number) =>
	s < 3600
		? intl.formatMessage({ id: "sentinel.duration.minutes" }, { n: s / 60 })
		: s < 86400
			? intl.formatMessage({ id: "sentinel.duration.hours" }, { n: s / 3600 })
			: intl.formatMessage({ id: "sentinel.duration.days" }, { n: s / 86400 });

interface Props {
	idPrefix: string;
	value: SentinelChallenge;
	onChange: (v: SentinelChallenge) => void;
}

export function SentinelChallengeFields({ idPrefix, value, onChange }: Props) {
	const set = (p: Partial<SentinelChallenge>) => onChange({ ...value, ...p });
	const ttls = TTLS.includes(value.ttl) ? TTLS : [...TTLS, value.ttl].sort((a, b) => a - b);
	return (
		<div className="row">
			<div className="col-md-4 mb-3">
				<label htmlFor={`${idPrefix}-mode`} className="form-label">
					<T id="sentinel.challenge.mode" />
				</label>
				<select
					id={`${idPrefix}-mode`}
					className="form-select"
					value={value.mode}
					onChange={(e) => set({ mode: e.target.value as SentinelChallenge["mode"] })}
				>
					<option value="js">{intl.formatMessage({ id: "sentinel.challenge.mode.js" })}</option>
					<option value="cookie">{intl.formatMessage({ id: "sentinel.challenge.mode.cookie" })}</option>
				</select>
				<div className="form-hint small">
					<T id={`sentinel.challenge.mode.${value.mode}.hint`} />
				</div>
			</div>
			<div className="col-md-4 mb-3">
				<label htmlFor={`${idPrefix}-bits`} className="form-label">
					<T id="sentinel.challenge.difficulty" />
				</label>
				<select
					id={`${idPrefix}-bits`}
					className="form-select"
					value={value.difficulty}
					disabled={value.mode !== "js"}
					onChange={(e) => set({ difficulty: Number(e.target.value) })}
				>
					{BITS.map((b) => (
						<option key={b} value={b}>
							{intl.formatMessage({ id: `sentinel.challenge.bits.${b}` })}
						</option>
					))}
				</select>
			</div>
			<div className="col-md-4 mb-3">
				<label htmlFor={`${idPrefix}-ttl`} className="form-label">
					<T id="sentinel.challenge.ttl" />
				</label>
				<select
					id={`${idPrefix}-ttl`}
					className="form-select"
					value={value.ttl}
					onChange={(e) => set({ ttl: Number(e.target.value) })}
				>
					{ttls.map((s) => (
						<option key={s} value={s}>
							{ttlLabel(s)}
						</option>
					))}
				</select>
				<label className="form-check mt-2 mb-0">
					<input
						type="checkbox"
						className="form-check-input"
						checked={value.bind === "ip_ua"}
						onChange={(e) => set({ bind: e.target.checked ? "ip_ua" : "ip" })}
					/>
					<span className="form-check-label small">
						<T id="sentinel.challenge.bind-ua" />
					</span>
				</label>
			</div>
			<div className="col-12 mb-3">
				<label className="form-check mb-0">
					<input
						type="checkbox"
						className="form-check-input"
						checked={value.pages === true}
						onChange={(e) => set({ pages: e.target.checked })}
					/>
					<span className="form-check-label">
						<T id="sentinel.challenge.pages" />
					</span>
				</label>
				<div className="form-hint small">
					<T id="sentinel.challenge.pages.hint" />
				</div>
			</div>
		</div>
	);
}
