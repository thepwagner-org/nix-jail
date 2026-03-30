---
name: debugging-production
description: Debug nix-jail on production host desktop-17. Load when investigating failed jobs, proxy issues, or service problems on desktop-17.
---
## Mistakes to Avoid

- **Mutating production.** Treat production as **read-only**. NEVER restart services, modify files, or run destructive commands on desktop-17. Diagnose and fix in the codebase; the user will explicitly tell you to redeploy.
- **Wrong service name.** The unit is `nixjaild.service`, not `nix-jail.service`.
- **Forgetting sudo.** Job directories under `/var/lib/nix-jail/jobs/` are root-owned. Use `sudo ls`, `sudo cat`, etc.
- **Skipping `nj`.** Use `nj list` and `nj attach <job_id>` for job status and logs. Don't scrape journalctl for job output.
- **Running alice without env.** Alice needs credential env vars (e.g. `ALICE_PROXY_PASSWORD`). Check `alice-config.toml` for `password_env` and `source_env` fields.

## Access

```bash
ssh desktop-17
```

## Services

| Unit | Role |
| --- | --- |
| `nixjaild.service` | nix-jail sandbox daemon (runs as root) |
| `forgejo-nix-ci.service` | Forgejo Actions runner that submits jobs (see `../forgejo-nix-ci` for its own debugging) |

## Querying Jobs

```bash
nj list                        # all recent jobs with status
nj attach <job_id>             # stream/replay job logs
nj attach <job_id> 2>&1 | tail -30   # just the ending
```

## Daemon Logs

```bash
journalctl -u nixjaild --since "10 minutes ago" --no-pager
journalctl -u nixjaild -f      # follow live
```

## Server Config

Config path is baked into the nix store. Find it via:

```bash
systemctl cat nixjaild.service   # shows ExecStart with -c <path>
cat /nix/store/...-nix-jail.toml # the config itself
```

Key fields: `proxy_binary` (path to alice), `credentials`, `state_dir`.
Secrets live in `/run/secrets/nix-jail.env` (loaded via `EnvironmentFile`).

## Job Directories

```
/var/lib/nix-jail/jobs/<job_id>/
  alice-config.toml    # proxy config for this job
  root/                # sandbox root (becomes / inside chroot)
  workspace/           # checked-out repo
```

All require `sudo` to read.

## Testing Alice Directly

If proxy startup is suspect, run alice manually with the job's config:

```bash
sudo ALICE_PROXY_PASSWORD=test \
  /path/to/alice --config /var/lib/nix-jail/jobs/<job_id>/alice-config.toml --json
```

The `--json` flag matches how nixjaild spawns it. Watch stderr for readiness:
nix-jail expects a line containing `"listening for connections"` within 10 seconds.
