import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export function titleCase(text: string) {
  return text.charAt(0) + text.slice(1).toLowerCase();
}

export function formatDuration(seconds: number) {
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} h`;
  return `${(seconds / 86400).toFixed(1)} days`;
}

export function formatDateTime(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

export function shortHash(hash: string, size = 12) {
  return hash ? `${hash.slice(0, size)}…` : "—";
}

export function percent(value: number) {
  return `${Math.round(value * 100)}%`;
}
