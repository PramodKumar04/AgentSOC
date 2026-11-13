import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export function Table({ className, ...props }: HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto" tabIndex={0}>
      <table className={cn("w-full border-collapse text-sm", className)} {...props} />
    </div>
  );
}

export function Th({ className, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope="col"
      className={cn("border-b border-border bg-subtle px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-muted whitespace-nowrap", className)}
      {...props}
    />
  );
}

export function SortableTh({ label, active, order, onSort, className }: {
  label: string; active: boolean; order: "asc" | "desc"; onSort: () => void; className?: string;
}) {
  const Icon = !active ? ArrowUpDown : order === "asc" ? ArrowUp : ArrowDown;
  return (
    <Th className={className} aria-sort={active ? (order === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" onClick={onSort} className="inline-flex items-center gap-1 uppercase hover:text-ink">
        {label}
        <Icon className={cn("size-3", active ? "text-ink" : "text-faint")} aria-hidden />
      </button>
    </Th>
  );
}

export function Td({ className, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("border-b border-border px-3 py-2.5 align-middle text-ink-2", className)} {...props} />;
}

export function Tr({ className, ...props }: HTMLAttributes<HTMLTableRowElement>) {
  return <tr className={cn("hover:bg-subtle/70", className)} {...props} />;
}
