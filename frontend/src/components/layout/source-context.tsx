// The active data source (synthetic demo or a LANL run). Shared by all pages and
// persisted per browser so a refresh keeps the analyst's context.
import { useQuery } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

import { api, type SourceRef } from "@/lib/api";

const STORAGE_KEY = "agentsoc.source";

interface SourceState {
  sources: SourceRef[];
  source: SourceRef | null;
  setSource: (key: string) => void;
  isLoading: boolean;
  error: unknown;
  refetch: () => void;
}

const SourceContext = createContext<SourceState | null>(null);

function readStored(): string | null {
  try { return window.localStorage.getItem(STORAGE_KEY); } catch { return null; }
}

export function SourceProvider({ children }: { children: ReactNode }) {
  const query = useQuery({ queryKey: ["sources"], queryFn: api.sources, staleTime: 60_000 });
  const [selected, setSelected] = useState<string | null>(readStored);

  const setSource = useCallback((key: string) => {
    setSelected(key);
    try { window.localStorage.setItem(STORAGE_KEY, key); } catch { /* storage unavailable */ }
  }, []);

  const value = useMemo<SourceState>(() => {
    const sources = query.data ?? [];
    const source = sources.find((s) => s.key === selected) ?? sources.find((s) => s.is_default) ?? null;
    return { sources, source, setSource, isLoading: query.isLoading, error: query.error,
             refetch: () => void query.refetch() };
  }, [query.data, query.isLoading, query.error, query, selected, setSource]);

  return <SourceContext.Provider value={value}>{children}</SourceContext.Provider>;
}

export function useSource(): SourceState {
  const ctx = useContext(SourceContext);
  if (!ctx) throw new Error("useSource must be used inside SourceProvider");
  return ctx;
}
