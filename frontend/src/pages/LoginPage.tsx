import { useQuery } from "@tanstack/react-query";
import { Loader2, LogIn, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/form";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export function LoginPage() {
  const { signIn } = useAuth();
  const status = useQuery({ queryKey: ["auth", "status"], queryFn: api.authStatus, retry: false });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try { await signIn(username.trim(), password); }
    catch (err) { setError(err instanceof Error ? err.message : "Sign-in failed."); }
    finally { setBusy(false); setPassword(""); }
  };

  return (
    <main className="flex min-h-full items-center justify-center bg-canvas px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2.5">
          <div className="flex size-9 items-center justify-center rounded-lg bg-brand text-white">
            <ShieldCheck className="size-5" aria-hidden />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-ink">Sign in to AgentSOC</h1>
            <p className="text-xs text-muted">Security operations workspace</p>
          </div>
        </div>
        {status.data?.setup_required && (
          <div role="note" className="mb-4 rounded-lg border border-medium/30 bg-medium-soft px-4 py-3 text-sm text-ink-2">
            <p className="font-medium text-ink">No accounts exist yet</p>
            An administrator must create the first account on the server with
            <code className="mx-1 rounded bg-surface px-1 font-mono text-[12px]">python scripts/manage_users.py create NAME --role admin</code>.
          </div>
        )}
        <form onSubmit={(e) => void submit(e)} className="space-y-4 rounded-card border border-border bg-surface p-5 shadow-card">
          <div className="space-y-1.5">
            <label htmlFor="login-username" className="text-sm font-medium text-ink">Username</label>
            <Input id="login-username" value={username} onChange={(e) => setUsername(e.target.value)}
              autoComplete="username" autoCapitalize="none" spellCheck={false} required className="w-full" />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="login-password" className="text-sm font-medium text-ink">Password</label>
            <Input id="login-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password" required className="w-full" />
          </div>
          {error && <p role="alert" className="text-sm text-critical">{error}</p>}
          <Button type="submit" variant="primary" className="w-full" disabled={busy}>
            {busy ? <Loader2 className="animate-spin" aria-hidden /> : <LogIn aria-hidden />}
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </div>
    </main>
  );
}
