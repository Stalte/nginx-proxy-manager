import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	getSentinelAlerts,
	getSentinelAutoban,
	getSentinelBans,
	getSentinelList,
	getSentinelLists,
	getSentinelRateLimits,
	getSentinelRules,
	getSentinelStatus,
	getSentinelUnderAttack,
	getSentinelUnderAttackEvents,
	type SentinelAlerts,
	type SentinelAutoban,
	type SentinelBan,
	type SentinelList,
	type SentinelRateLimit,
	type SentinelRule,
	type SentinelStatus,
	type SentinelUnderAttackEvent,
	type SentinelUnderAttackHost,
	saveSentinelList,
	saveSentinelRule,
} from "src/api/backend";

const useSentinelStatus = (options = {}) =>
	useQuery<SentinelStatus, Error>({
		queryKey: ["sentinel-status"],
		queryFn: getSentinelStatus,
		staleTime: 15 * 1000,
		...options,
	});

const useSentinelRules = (options = {}) =>
	useQuery<SentinelRule[], Error>({
		queryKey: ["sentinel-rules"],
		queryFn: getSentinelRules,
		staleTime: 60 * 1000,
		...options,
	});

const useSentinelLists = (options = {}) =>
	useQuery<SentinelList[], Error>({
		queryKey: ["sentinel-lists"],
		queryFn: getSentinelLists,
		staleTime: 30 * 1000,
		...options,
	});

const useSentinelList = (id: number | "new", options = {}) =>
	useQuery<SentinelList | null, Error>({
		queryKey: ["sentinel-list", id],
		queryFn: () => (id === "new" ? Promise.resolve(null) : getSentinelList(id)),
		staleTime: 0,
		...options,
	});

const useSentinelUnderAttack = (options = {}) =>
	useQuery<SentinelUnderAttackHost[], Error>({
		queryKey: ["sentinel-under-attack"],
		queryFn: getSentinelUnderAttack,
		staleTime: 10 * 1000,
		...options,
	});

const useSentinelUnderAttackEvents = (options = {}) =>
	useQuery<SentinelUnderAttackEvent[], Error>({
		queryKey: ["sentinel-under-attack-events"],
		queryFn: getSentinelUnderAttackEvents,
		staleTime: 10 * 1000,
		...options,
	});

const useSentinelAlerts = (options = {}) =>
	useQuery<SentinelAlerts, Error>({
		queryKey: ["sentinel-alerts"],
		queryFn: getSentinelAlerts,
		staleTime: 0,
		...options,
	});

const useSentinelBans = (options = {}) =>
	useQuery<SentinelBan[], Error>({
		queryKey: ["sentinel-bans"],
		queryFn: getSentinelBans,
		staleTime: 10 * 1000,
		...options,
	});

const useSentinelAutoban = (options = {}) =>
	useQuery<SentinelAutoban, Error>({
		queryKey: ["sentinel-autoban"],
		queryFn: getSentinelAutoban,
		staleTime: 0,
		...options,
	});

const useSentinelRateLimits = (options = {}) =>
	useQuery<SentinelRateLimit[], Error>({
		queryKey: ["sentinel-rate-limits"],
		queryFn: getSentinelRateLimits,
		staleTime: 10 * 1000,
		...options,
	});

const useInvalidateSentinel = () => {
	const queryClient = useQueryClient();
	return () => {
		queryClient.invalidateQueries({ queryKey: ["sentinel-rules"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-lists"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-list"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-status"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-under-attack"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-under-attack-events"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-alerts"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-bans"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-autoban"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-rate-limits"] });
		queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
	};
};

const useSetSentinelRule = () => {
	const invalidate = useInvalidateSentinel();
	return useMutation({
		mutationFn: (values: Partial<SentinelRule>) => saveSentinelRule(values),
		onSettled: invalidate,
	});
};

const useSetSentinelList = () => {
	const invalidate = useInvalidateSentinel();
	return useMutation({
		mutationFn: (values: Partial<SentinelList>) => saveSentinelList(values),
		onSettled: invalidate,
	});
};

export {
	useInvalidateSentinel,
	useSentinelAlerts,
	useSentinelAutoban,
	useSentinelBans,
	useSentinelList,
	useSentinelLists,
	useSentinelRateLimits,
	useSentinelRules,
	useSentinelStatus,
	useSentinelUnderAttack,
	useSentinelUnderAttackEvents,
	useSetSentinelList,
	useSetSentinelRule,
};
