# Security foundations (Phase A)

What AgentSOC protects, how, and what it does not yet do. Written for whoever installs and
operates it.

## Accounts and sign-in

- Two roles. **Administrators** manage accounts and, from Phase D, data sources,
  credentials, mappings, synchronisation and AI permissions. **Analysts** review events,
  incidents, risk, attack analysis, investigations and the audit trail.
- There is no default account. Create the first administrator on the server:

  ```powershell
  python scripts/manage_users.py create alice --role admin
  ```

  The password is read from a hidden prompt (or, for automation, from the environment
  variable named by `--password-env`). It is never accepted on the command line.
- Passwords: 12–128 characters, not containing the username. Stored as scrypt hashes
  (Python standard library; n=2^15, r=8, p=1, 16-byte random salt).
- Sessions: a random token in an `HttpOnly`, `SameSite=Strict` cookie. The database stores
  only its SHA-256, so a copy of the database cannot be used to sign in. Sessions end after
  30 idle minutes and after 8 hours in any case (`AGENTSOC_SESSION_IDLE_MINUTES`,
  `AGENTSOC_SESSION_MAX_HOURS`), and immediately when the user signs out, has their role
  changed, is disabled, or has their password reset.
- Every state-changing request needs the session's CSRF token in `X-CSRF-Token`. The page
  keeps it in memory only. Sign-in accepts JSON only, which a cross-site form cannot send.
- Five wrong passwords lock the account for 15 minutes (`AGENTSOC_LOGIN_MAX_FAILURES`,
  `AGENTSOC_LOGIN_LOCKOUT_MINUTES`). Twenty failures from one address in five minutes are
  refused for a while. The message is the same for a wrong password and an unknown,
  locked or disabled account.
- There is always at least one active administrator, and nobody can change their own role
  or disable themselves.
- Responses carry `nosniff`, `X-Frame-Options: DENY`, a restrictive Content-Security-Policy
  and, for the API, `Cache-Control: no-store`.

**Set `AGENTSOC_COOKIE_SECURE=true` whenever AgentSOC is reached over HTTPS**, which it must
be for anything beyond a single machine. It is off by default only because the local
prototype runs on plain `http://127.0.0.1`.

## Stored credentials

Database passwords and connection strings (used from Phase D) are encrypted with Fernet
(AES-128-CBC with HMAC-SHA256, from the `cryptography` package) before they reach the
application database. They are never returned by the API, written to the audit log, or
included in error messages, and any secret the server decrypts is redacted from its logs.

### Key generation

```powershell
python scripts/manage_credentials.py generate-key
```

Put the printed key in `AGENTSOC_CREDENTIAL_KEY` (for example in `.env`, which is not
committed). Without it, credential storage is disabled; nothing falls back to plaintext.

### Backup

**Back up the key separately from the database.** Losing every configured key makes the
stored credentials unrecoverable: they must be entered again. A backup that holds both the
database and the key gives whoever has it the credentials.

### Rotation

1. Generate a new key.
2. Set `AGENTSOC_CREDENTIAL_KEY="NEW_KEY,OLD_KEY"` and restart.
3. Run `python scripts/manage_credentials.py rotate`, which re-encrypts everything with the
   first key.
4. Remove `OLD_KEY` from the variable and restart.

### Limitations

- The key lives in the server's environment. Anyone who can read both the environment and
  the database can decrypt. A production deployment should replace
  `EncryptedCredentialStore` with a secret manager (Vault, a cloud KMS, Windows Credential
  Manager); callers use the `CredentialStore` interface and would not change.
- Rotation is manual and stops the first time a credential cannot be decrypted.

## Audit trail

Sign-ins (successful and failed), sign-outs, password changes and resets, account changes
and credential operations are added to the hash-chained activity log with the acting user.
Passwords, tokens and secrets are never recorded. A failed sign-in for an unknown account
is recorded without the typed username, in case a password was typed into that box. The
server and the command-line tools take a shared file lock, so concurrent writers cannot
break the chain. The chain shows tampering; it does not prevent someone who can rewrite the
whole file from rebuilding it.

## Not yet done

- No multi-factor authentication or single sign-on.
- No self-service password recovery: an administrator resets passwords.
- Rate limits are per server process and reset on restart.
- Field-level masking of sensitive values for analysts is not implemented.
