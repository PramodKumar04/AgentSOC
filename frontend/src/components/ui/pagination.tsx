import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "./button";

export function Pagination({ page, pageSize, total, onPage, noun = "items" }: {
  page: number; pageSize: number; total: number; onPage: (page: number) => void; noun?: string;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex items-center justify-between gap-3 px-4 py-3 text-xs text-muted">
      <span className="tabular">
        {from}–{to} of {total.toLocaleString()} {noun}
      </span>
      <div className="flex items-center gap-1">
        <Button size="icon" variant="ghost" aria-label="Previous page" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          <ChevronLeft aria-hidden />
        </Button>
        <span className="tabular px-2">Page {page} of {pages}</span>
        <Button size="icon" variant="ghost" aria-label="Next page" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          <ChevronRight aria-hidden />
        </Button>
      </div>
    </div>
  );
}
