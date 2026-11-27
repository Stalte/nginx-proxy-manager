import { IconAlertTriangle, IconCircleCheck, IconList, IconShieldLock, IconWorld } from "@tabler/icons-react";
import cn from "classnames";
import { type ReactNode, useState } from "react";
import { useSentinelLists, useSentinelRules, useSentinelStatus } from "src/hooks";
import { formatDateTime, getLocale, T } from "src/locale";
import Lists from "./Lists";
import Rules from "./Rules";
import UnderAttack from "./UnderAttack";

function Tile({
	icon,
	color,
	label,
	value,
	sub,
}: {
	icon: ReactNode;
	color: string;
	label: ReactNode;
	value: ReactNode;
	sub?: ReactNode;
}) {
	return (
		<div className="col-sm-6 col-lg-3">
			<div className="card card-sm h-100">
				<div className="card-body">
					<div className="row align-items-center">
						<div className="col-auto">
							<span className={cn("avatar", `bg-${color}-lt`)}>{icon}</span>
						</div>
						<div className="col">
							<div className="text-secondary small">{label}</div>
							<div className="h3 m-0">{value}</div>
							{sub ? <div className="text-secondary small text-truncate">{sub}</div> : null}
						</div>
					</div>
				</div>
			</div>
		</div>
	);
}

export default function Layout() {
	const [tab, setTab] = useState<"rules" | "lists" | "under-attack">("rules");
	const status = useSentinelStatus({ refetchInterval: 30 * 1000 });
	const rules = useSentinelRules();
	const lists = useSentinelLists();

	const active = (rules.data || []).filter((r) => r.enabled).length;
	const feeds = (lists.data || []).filter((l) => l.sourceUrl);
	const failing = feeds.filter((l) => l.fetchError && !l.changedOn).length;
	const deploy = status.data?.deploy;
	const geo = status.data?.geoip;
	const attacked = status.data?.underAttack?.active || 0;

	return (
		<>
			<div className="row row-cards mt-2">
				<Tile
					icon={<IconShieldLock size={20} />}
					color="red"
					label={<T id="sentinel.tile.rules" />}
					value={`${active} / ${(rules.data || []).length}`}
					sub={<T id="sentinel.tile.rules.sub" />}
				/>
				<Tile
					icon={<IconList size={20} />}
					color="cyan"
					label={<T id="sentinel.tile.lists" />}
					value={(lists.data || []).length}
					sub={
						failing ? (
							<span className="text-warning">
								<T id="sentinel.tile.lists.failing" data={{ n: failing }} />
							</span>
						) : (
							<T id="sentinel.tile.lists.sub" data={{ n: feeds.length }} />
						)
					}
				/>
				<Tile
					icon={deploy?.ok === false ? <IconAlertTriangle size={20} /> : <IconCircleCheck size={20} />}
					color={deploy?.ok === false ? "orange" : "green"}
					label={<T id="sentinel.tile.deploy" />}
					value={<T id={deploy?.ok === false ? "sentinel.tile.deploy.failed" : "sentinel.tile.deploy.ok"} />}
					sub={deploy?.at ? formatDateTime(deploy.at, getLocale()) : null}
				/>
				<Tile
					icon={<IconWorld size={20} />}
					color="purple"
					label={<T id="sentinel.tile.geoip" />}
					value={
						<T
							id={
								geo?.downloading
									? "sentinel.tile.geoip.downloading"
									: geo?.available
										? "sentinel.tile.geoip.ready"
										: "sentinel.tile.geoip.none"
							}
						/>
					}
					sub={geo?.error ? <span className="text-warning">{geo.error}</span> : geo?.attribution}
				/>
			</div>
			{attacked ? (
				<div className="alert alert-danger mt-3 mb-0 d-flex align-items-center">
					<IconAlertTriangle size={18} className="me-2" />
					<span className="me-auto">
						<T id="sentinel.under-attack.banner" data={{ n: attacked }} />
					</span>
					<button type="button" className="btn btn-sm btn-danger" onClick={() => setTab("under-attack")}>
						<T id="sentinel.under-attack.view" />
					</button>
				</div>
			) : null}
			{deploy?.ok === false && deploy.error ? (
				<div className="alert alert-warning mt-3 mb-0">
					<pre className="m-0 small" style={{ whiteSpace: "pre-wrap" }}>
						{deploy.error}
					</pre>
				</div>
			) : null}
			<div className="card mt-3">
				<div className="card-status-top bg-red" />
				<div className="card-header">
					<ul className="nav nav-tabs card-header-tabs">
						<li className="nav-item">
							<button
								type="button"
								className={cn("nav-link", tab === "rules" && "active")}
								onClick={() => setTab("rules")}
							>
								<T id="sentinel.rules" />
							</button>
						</li>
						<li className="nav-item">
							<button
								type="button"
								className={cn("nav-link", tab === "lists" && "active")}
								onClick={() => setTab("lists")}
							>
								<T id="sentinel.lists" />
							</button>
						</li>
						<li className="nav-item">
							<button
								type="button"
								className={cn("nav-link", tab === "under-attack" && "active")}
								onClick={() => setTab("under-attack")}
							>
								<T id="sentinel.under-attack" />
								{attacked ? <span className="badge bg-red text-red-fg ms-2">{attacked}</span> : null}
							</button>
						</li>
					</ul>
				</div>
				{tab === "rules" ? <Rules /> : tab === "lists" ? <Lists /> : <UnderAttack />}
			</div>
		</>
	);
}
