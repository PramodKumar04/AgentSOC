import { Link } from "react-router";

import { Card, CardBody } from "@/components/ui/card";

export function NotFoundPage() {
  return (
    <Card>
      <CardBody className="py-12 text-center">
        <p className="font-medium text-ink">Page not found</p>
        <Link to="/" className="mt-2 inline-block text-sm text-brand hover:underline">Go to overview</Link>
      </CardBody>
    </Card>
  );
}
