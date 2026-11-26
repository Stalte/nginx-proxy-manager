import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	getSentinelList,
	getSentinelLists,
	getSentinelRules,
	getSentinelStatus,
	type SentinelList,
	type SentinelRule,
	type SentinelStatus,
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

const useInvalidateSentinel = () => {
	const queryClient = useQueryClient();
	return () => {
		queryClient.invalidateQueries({ queryKey: ["sentinel-rules"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-lists"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-list"] });
		queryClient.invalidateQueries({ queryKey: ["sentinel-status"] });
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
	useSentinelList,
	useSentinelLists,
	useSentinelRules,
	useSentinelStatus,
	useSetSentinelList,
	useSetSentinelRule,
};
