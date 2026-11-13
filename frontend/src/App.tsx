import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { BrowserRouter, Route, Routes } from "react-router";

import { AppShell } from "@/components/layout/app-shell";
import { SourceProvider } from "@/components/layout/source-context";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { AuthProvider, useAuth } from "@/lib/auth";
import { AccountPage, UsersPage } from "@/pages/AccountPages";
import { ConnectionsPage } from "@/pages/ConnectionsPage";
import { ActivityPage } from "@/pages/ActivityPage";
import { DataSourcesPage } from "@/pages/DataSourcesPage";
import { EvidencePage } from "@/pages/EvidencePage";
import { IncidentDetailPage } from "@/pages/IncidentDetailPage";
import { IncidentsPage } from "@/pages/IncidentsPage";
import { InvestigationDetailPage, InvestigationsPage } from "@/pages/InvestigationsPage";
import { LoginPage } from "@/pages/LoginPage";
import { NotFoundPage } from "@/pages/NotFoundPage";
import { OverviewPage } from "@/pages/OverviewPage";

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 15_000 },
      mutations: { retry: 0 },
    },
  });
}

function Gate() {
  const { session, isLoading, error, retry } = useAuth();
  if (isLoading) return <LoadingBlock label="Connecting to AgentSOC…" />;
  if (error) return <ErrorState error={error} onRetry={retry} />;
  if (!session) return <LoginPage />;
  return (
    <SourceProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
          <Route path="investigations" element={<InvestigationsPage />} />
          <Route path="investigations/:investigationId" element={<InvestigationDetailPage />} />
          <Route path="evidence" element={<EvidencePage />} />
          <Route path="data-sources" element={<DataSourcesPage />} />
          <Route path="activity" element={<ActivityPage />} />
          <Route path="account" element={<AccountPage />} />
          <Route path="admin/users" element={<UsersPage />} />
          <Route path="admin/connections" element={<ConnectionsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </SourceProvider>
  );
}

export function AppRoutes() {
  return <AuthProvider><Gate /></AuthProvider>;
}

export function App() {
  const [client] = useState(makeQueryClient);
  return (
    <QueryClientProvider client={client}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </QueryClientProvider>
  );
}
