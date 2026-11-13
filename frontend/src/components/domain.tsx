// Small domain components shared across pages (severity, provenance, status, confidence).
import { Bot, Cpu, Database, FlaskConical, Gauge, Landmark } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { InvestigationStatus, Provenance, Severity } from "@/lib/api";
import { cn, percent, titleCase } from "@/lib/utils";

const SEVERITY_TONE = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" } as const;
// Hex values mirror the design tokens in index.css. SVG presentation attributes (used by
// Recharts) do not resolve CSS var(), so charts need literal colours.
export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "#b91c1c", HIGH: "#c2410c", MEDIUM: "#b45309", LOW: "#475569",
};
export const CHART = { brand: "#2563eb", grid: "#e3e6eb", muted: "#64748b", ink: "#334155", hover: "#f8fafc" };

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge tone={SEVERITY_TONE[severity]}>
      <span className="size-1.5 rounded-full" style={{ background: SEVERITY_COLOR[severity] }} aria-hidden />
      {titleCase(severity)}
    </Badge>
  );
}

/** RSEM incident risk. Kept visually distinct from the detection severity badge. */
export function RiskBadge({ band, score }: { band?: Severity | null; score?: number | null }) {
  if (!band || score === null || score === undefined) {
    return <span className="text-xs text-faint" title="No verified risk assessment for this incident">Not assessed</span>;
  }
  return (
    <Badge tone={SEVERITY_TONE[band]} title="RSEM incident risk (0–100). A heuristic, not a probability of compromise.">
      <Gauge className="size-3" aria-hidden />
      {titleCase(band)} <span className="tabular">{score.toFixed(1)}</span>
    </Badge>
  );
}

export function ProvenanceBadge({ provenance, long = false }: { provenance: Provenance; long?: boolean }) {
  if (provenance === "synthetic") {
    return (
      <Badge tone="synthetic" title="Generated demonstration data — not real activity">
        <FlaskConical className="size-3" aria-hidden />
        {long ? "Synthetic demonstration data" : "Synthetic"}
      </Badge>
    );
  }
  if (provenance === "organization" || provenance === "upload") {
    const org = provenance === "organization";
    return (
      <Badge tone="real" title={org ? "Read from an organisational database through a configured mapping" : "Uploaded file; provenance asserted by the uploader"}>
        <Database className="size-3" aria-hidden />
        {org ? (long ? "Organisational database" : "Organisation") : (long ? "Uploaded data" : "Uploaded")}
      </Badge>
    );
  }
  return (
    <Badge tone="real" title="Real LANL 2015 authentication data (sampled, anonymised)">
      <Landmark className="size-3" aria-hidden />
      {long ? "Real LANL 2015 data" : "LANL (real)"}
    </Badge>
  );
}

export function InvestigationBadge({ status }: { status: InvestigationStatus }) {
  if (status === "completed") return <Badge tone="ok"><Bot className="size-3" aria-hidden />Investigated</Badge>;
  if (status === "completed_limited")
    return <Badge tone="warn" title="Investigated with limited (deterministic) analysis"><Cpu className="size-3" aria-hidden />Limited</Badge>;
  if (status === "stale") return <Badge tone="neutral">Outdated</Badge>;
  return <span className="text-xs text-faint">Not investigated</span>;
}

export function ConfidenceBar({ value, tone = "brand", className }: {
  value: number; tone?: "brand" | "malicious" | "benign"; className?: string;
}) {
  const color = tone === "malicious" ? "bg-critical" : tone === "benign" ? "bg-ok" : "bg-brand";
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div
        className="h-1.5 w-full min-w-16 overflow-hidden rounded-full bg-border"
        role="meter" aria-valuemin={0} aria-valuemax={1} aria-valuenow={value}
        aria-label={`Confidence ${percent(value)}`}
      >
        <div className={cn("h-full rounded-full", color)} style={{ width: `${Math.round(value * 100)}%` }} />
      </div>
      <span className="tabular w-9 text-right text-xs font-medium text-ink-2">{percent(value)}</span>
    </div>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("font-mono text-[12.5px] text-ink", className)}>{children}</span>;
}
