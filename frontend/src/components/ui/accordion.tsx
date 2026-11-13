import * as AccordionPrimitive from "@radix-ui/react-accordion";
import { ChevronDown } from "lucide-react";
import type { ComponentProps, ReactNode } from "react";

import { cn } from "@/lib/utils";

export const Accordion = AccordionPrimitive.Root;

export function AccordionItem({ className, ...props }: ComponentProps<typeof AccordionPrimitive.Item>) {
  return <AccordionPrimitive.Item className={cn("border-b border-border last:border-b-0", className)} {...props} />;
}

export function AccordionTrigger({ children, className, ...props }:
  ComponentProps<typeof AccordionPrimitive.Trigger> & { children: ReactNode }) {
  return (
    <AccordionPrimitive.Header className="flex">
      <AccordionPrimitive.Trigger
        className={cn("group flex flex-1 items-center justify-between gap-3 px-5 py-3.5 text-left text-sm hover:bg-subtle/70", className)}
        {...props}
      >
        {children}
        <ChevronDown className="size-4 shrink-0 text-muted transition-transform group-data-[state=open]:rotate-180" aria-hidden />
      </AccordionPrimitive.Trigger>
    </AccordionPrimitive.Header>
  );
}

export function AccordionContent({ className, ...props }: ComponentProps<typeof AccordionPrimitive.Content>) {
  return <AccordionPrimitive.Content className={cn("px-5 pb-4", className)} {...props} />;
}
