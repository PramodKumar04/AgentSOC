// "Your account" (any user) and "Users" (administrators). The server enforces every rule;
// these pages only collect input and show the result.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { PageHeader } from "@/components/layout/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/form";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api, type AdminUser, type Role } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime } from "@/lib/utils";

const POLICY = "At least 12 characters, not containing the username.";

function Field({ id, label, children }: { id: string; label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="text-sm font-medium text-ink">{label}</label>
      {children}
    </div>
  );
}

function Result({ error, done }: { error: unknown; done?: string | false }) {
  if (error) return <p role="alert" className="text-sm text-critical">{error instanceof Error ? error.message : "Request failed."}</p>;
  return done ? <p role="status" className="text-sm text-ok">{done}</p> : null;
}

export function AccountPage() {
  const { session, replaceSession } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const change = useMutation({
    mutationFn: () => api.changePassword(current, next),
    onSuccess: (fresh) => { replaceSession(fresh); setCurrent(""); setNext(""); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); change.mutate(); };
  return (
    <>
      <PageHeader title="Your account" description={`Signed in as ${session?.user.username} (${session?.user.role}).`} />
      <Card className="max-w-lg">
        <CardHeader title="Change password" description="Signs out your other sessions." />
        <CardBody>
          <form onSubmit={submit} className="space-y-4">
            <Field id="current-password" label="Current password">
              <Input id="current-password" type="password" autoComplete="current-password" value={current}
                onChange={(e) => setCurrent(e.target.value)} required className="w-full" />
            </Field>
            <Field id="new-password" label="New password">
              <Input id="new-password" type="password" autoComplete="new-password" value={next}
                onChange={(e) => setNext(e.target.value)} required className="w-full" aria-describedby="pw-policy" />
            </Field>
            <p id="pw-policy" className="text-xs text-muted">{POLICY}</p>
            <Result error={change.error} done={change.isSuccess && "Password changed."} />
            <Button type="submit" variant="primary" disabled={change.isPending}>Change password</Button>
          </form>
        </CardBody>
      </Card>
    </>
  );
}

function UserRow({ user, self }: { user: AdminUser; self: boolean }) {
  const client = useQueryClient();
  const refresh = () => void client.invalidateQueries({ queryKey: ["admin", "users"] });
  const update = useMutation({ mutationFn: (patch: { role?: Role; disabled?: boolean }) => api.updateUser(user.username, patch), onSuccess: refresh });
  const [resetting, setResetting] = useState(false);
  const [password, setPassword] = useState("");
  const reset = useMutation({
    mutationFn: () => api.resetPassword(user.username, password),
    onSuccess: () => { setPassword(""); setResetting(false); refresh(); },
  });
  return (
    <>
      <Tr>
        <Td className="font-medium text-ink">{user.username}{self && <span className="ml-1.5 text-xs text-muted">(you)</span>}</Td>
        <Td>
          <label className="sr-only" htmlFor={`role-${user.username}`}>Role for {user.username}</label>
          <Select id={`role-${user.username}`} value={user.role} disabled={self || update.isPending}
            onChange={(e) => update.mutate({ role: e.target.value as Role })} className="h-8 text-xs">
            <option value="analyst">Analyst</option>
            <option value="admin">Administrator</option>
          </Select>
        </Td>
        <Td>{user.disabled ? <Badge tone="neutral">Disabled</Badge> : user.locked ? <Badge tone="warn">Locked</Badge> : <Badge tone="ok">Active</Badge>}</Td>
        <Td className="whitespace-nowrap text-muted">{formatDateTime(user.password_changed_at)}</Td>
        <Td>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" disabled={self || update.isPending} onClick={() => update.mutate({ disabled: !user.disabled })}>
              {user.disabled ? "Enable" : "Disable"}
            </Button>
            <Button size="sm" onClick={() => setResetting(!resetting)} aria-expanded={resetting}>Reset password</Button>
          </div>
        </Td>
      </Tr>
      {(resetting || update.error) && (
        <tr><td colSpan={5} className="border-b border-border bg-subtle px-4 py-3">
          <Result error={update.error} />
          {resetting && (
            <form onSubmit={(e) => { e.preventDefault(); reset.mutate(); }} className="flex flex-wrap items-end gap-3">
              <Field id={`reset-${user.username}`} label={`New password for ${user.username}`}>
                <Input id={`reset-${user.username}`} type="password" autoComplete="new-password" value={password}
                  onChange={(e) => setPassword(e.target.value)} required className="w-64" />
              </Field>
              <Button type="submit" variant="primary" size="sm" disabled={reset.isPending}>Set password</Button>
              <Result error={reset.error} />
            </form>
          )}
        </td></tr>
      )}
    </>
  );
}

export function UsersPage() {
  const { session } = useAuth();
  const client = useQueryClient();
  const users = useQuery({ queryKey: ["admin", "users"], queryFn: api.users,
                           enabled: session?.user.role === "admin" });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const create = useMutation({
    mutationFn: () => api.createUser(username.trim(), password, role),
    onSuccess: () => { setUsername(""); setPassword(""); void client.invalidateQueries({ queryKey: ["admin", "users"] }); },
  });
  if (session?.user.role !== "admin") {
    return <ErrorState error={new Error("Administrator access is required.")} />;
  }
  return (
    <>
      <PageHeader title="Users" description="Administrators manage accounts, data sources and AI permissions. Analysts review security data." />
      <Card className="mb-6">
        <CardHeader title="Accounts" />
        {users.isLoading ? <LoadingBlock label="Loading accounts…" />
          : users.error ? <ErrorState error={users.error} onRetry={() => void users.refetch()} />
          : (
            <Table>
              <thead><tr><Th>User</Th><Th>Role</Th><Th>Status</Th><Th>Password changed</Th><Th>Actions</Th></tr></thead>
              <tbody>{users.data!.map((u) => <UserRow key={u.username} user={u} self={u.username === session.user.username} />)}</tbody>
            </Table>
          )}
      </Card>
      <Card className="max-w-lg">
        <CardHeader title="Add an account" />
        <CardBody>
          <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="space-y-4">
            <Field id="new-username" label="Username">
              <Input id="new-username" value={username} onChange={(e) => setUsername(e.target.value)} required
                autoComplete="off" autoCapitalize="none" spellCheck={false} className="w-full" />
            </Field>
            <Field id="new-user-password" label="Initial password">
              <Input id="new-user-password" type="password" autoComplete="new-password" value={password}
                onChange={(e) => setPassword(e.target.value)} required className="w-full" />
            </Field>
            <p className="text-xs text-muted">{POLICY}</p>
            <Field id="new-role" label="Role">
              <Select id="new-role" value={role} onChange={(e) => setRole(e.target.value as Role)} className="w-full">
                <option value="analyst">Analyst</option>
                <option value="admin">Administrator</option>
              </Select>
            </Field>
            <Result error={create.error} done={create.isSuccess && "Account created."} />
            <Button type="submit" variant="primary" disabled={create.isPending}>Add account</Button>
          </form>
        </CardBody>
      </Card>
    </>
  );
}
