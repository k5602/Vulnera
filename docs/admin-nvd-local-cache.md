# Admin Guide: Local NVD Cache with nvd_cve

Status: Draft
Audience: Operators / SREs / Self-hosted users
Scope: Managing a local NVD (National Vulnerability Database) dataset used by Vulnera via the `nvd_cve` crate.

## Why a local NVD cache?

- Reliability: Avoid NVD API rate limits and intermittent network issues.
- Performance: Fast, local CVE lookup for dependency analysis.
- Predictability: Stable results across repeated analyses.

Vulnera treats OSV as the primary source and uses NVD to enrich results. A local NVD cache ensures NVD data is available without depending on remote API quotas.

## How it works (high level)

- Vulnera’s NVD adapter uses the `nvd_cve` library to query CVEs from a local dataset on disk (read-only during runtime).
- You manage the dataset lifecycle (download, update, rotate) out-of-band with Vulnera using upstream `nvd_cve` tooling and documentation.
- If the dataset is missing or unreadable, Vulnera degrades gracefully by returning only OSV (and GHSA if configured) results and logging a warning.

## Requirements

- Disk space: NVD datasets include yearly JSON feeds (and “modified/recent” deltas). Size varies by year and retention policy. Plan for multiple GB of free space and monitor growth.
- Connectivity: Initial bootstrap and periodic updates require internet access to NVD feeds (unless you mirror them internally).
- Permissions: The Vulnera process must have read access to the dataset directory. If you run updates under the same account, it also needs write permissions.

## Configuration

Use environment variables (double-underscore naming) to configure the local dataset path and update policy.

- VULNERA**CACHE**NVD\_\_LOCAL_PATH
  - Absolute or relative path to the directory containing the `nvd_cve` dataset (e.g., /var/lib/vulnera/nvd).
  - The directory must exist and be readable by the Vulnera service user.

- VULNERA**CACHE**NVD\_\_UPDATE_ON_START (optional, future-facing)
  - Boolean flag (true/false). If you later enable automatic updates at startup, Vulnera can attempt an update. When not implemented or disabled, no automatic updates occur.

Example linux service environment (adapt to your init system):
ENV=production
VULNERA**CACHE**NVD**LOCAL_PATH=/var/lib/vulnera/nvd
VULNERA**CACHE**NVD**UPDATE_ON_START=false

Notes:

- These names follow Vulnera’s ENV override convention: VULNERA**SECTION**FIELD.
- If unset, Vulnera will try a sensible default under the working directory (e.g., .vulnera_cache/nvd). Production deployments should set an explicit absolute path.

## Bootstrapping the dataset

You control dataset initialization using the `nvd_cve` project. The crate publishes a command-line binary (“nvd_cve”) you can install with Cargo. Follow upstream documentation for exact commands and flags.

General steps:

1. Create the dataset directory:
   - mkdir -p /var/lib/vulnera/nvd
   - chown <service_user>:<service_group> /var/lib/vulnera/nvd

2. Install the nvd_cve CLI (on a build/ops host with Cargo available):
   - cargo install nvd_cve

3. Use the nvd_cve CLI to download and initialize the local NVD dataset under the configured path.
   - Consult the nvd_cve README for the recommended sync/update command.
   - If your environment uses a proxy or blocklists, configure the CLI accordingly.

4. Verify dataset presence (list the directory, check for files and expected structure).

5. Start or restart Vulnera with VULNERA**CACHE**NVD\_\_LOCAL_PATH pointing to this directory.

If you run Vulnera in a container:

- Prepare the dataset in a persistent volume/mount on the host.
- Mount the prepared dataset into the container at the same configured path (read-only is recommended during normal operation).

## Updating the dataset

Frequency:

- NVD publishes updates frequently. A daily schedule is a pragmatic default; tune to your needs.

Approaches:

- Cron/systemd timer on the host:
  - Run the nvd_cve CLI periodically to pull updates into the same dataset directory.
  - Ensure the process has write permission to the path.
- Out-of-band preparation + atomic swap:
  - Download updates into a new directory (e.g., /var/lib/vulnera/nvd-YYYYMMDD).
  - Verify integrity and completeness.
  - Atomically update a symlink (/var/lib/vulnera/nvd -> nvd-YYYYMMDD) to switch versions without downtime.
  - This approach supports quick rollback (re-point the symlink).

Operational note:

- Vulnera only needs read access. If you rotate the directory, ensure the final path matches VULNERA**CACHE**NVD\_\_LOCAL_PATH (or a symlink to it).

## Permissions and ownership

- Recommended:
  - Directory owner: root (or an ops/admin account).
  - Group: vulnera (or an appropriate service group).
  - Mode:
    - If Vulnera only reads: 0755 for directories, 0644 for files.
    - If the same user updates and runs Vulnera: ensure write permissions.
- Keep the dataset immutable during analysis (updates should happen in a controlled maintenance window or with atomic swaps).

## Observability and troubleshooting

Common symptoms:

- “NVD local dataset not found” or “access denied” in logs:
  - Check that VULNERA**CACHE**NVD\_\_LOCAL_PATH points to the correct, populated directory.
  - Check permissions: the Vulnera process user must be able to read the dataset.
- “Empty NVD results”:
  - If OSV results still appear, Vulnera is running. It may skip NVD because the dataset is missing, corrupted, or unreadable.
  - Verify dataset structure and try a fresh sync with the nvd_cve CLI.
- Slow queries despite local cache:
  - Confirm the dataset is on local SSD or a fast volume.
  - Avoid remote mounts or network filesystems when possible.

Recommended monitoring:

- Disk usage of the dataset path.
- File count and last modification times in the dataset directory (to confirm updates are happening).
- Vulnera logs around analysis for “NVD initialized” or similar informational messages (log formats may evolve).

## Disk capacity planning

- Dataset size varies and grows over time. Monitor usage and plan headroom (multiple GB recommended).
- If using atomic swaps (symlink strategy), updates temporarily require 2x disk space (old + new).
- Enforce retention (keep N most recent dataset versions) and prune older ones to reclaim space.

## Backup and rollback

- Optionally back up the dataset directory or the latest versioned dataset.
- Rollback is trivial with the symlink strategy:
  - Re-point the symlink to the prior dataset.
  - No Vulnera restart is typically required if the symlink path is stable; if in doubt, restart the service.

## CI and local development

- CI: avoid large network downloads. For tests, use a minimal, pre-baked dataset (small subset) stored as an artifact or repository fixture (ensure licensing/compliance).
- Local dev:
  - Use a small dataset directory under the project (e.g., .vulnera_cache/nvd).
  - Point VULNERA**CACHE**NVD\_\_LOCAL_PATH to it.
  - Developers can skip NVD setup entirely; Vulnera will still return OSV (and GHSA if configured) results.

## Security considerations

- Ensure downloads originate from trusted sources (TLS-enabled endpoints).
- If you mirror NVD feeds internally, secure the mirror and access controls.
- Run Vulnera with least privilege; avoid granting write permissions to the dataset in production unless necessary.
- Treat the dataset directory as data-only; do not store secrets or executable content there.

## Frequently asked questions (FAQ)

Q: What happens if the dataset is missing?

- Vulnera continues with OSV (and GHSA if configured), logs a warning, and returns results without NVD enrichment.

Q: Does Vulnera update NVD feeds automatically?

- Automatic updates are not assumed. You should manage updates externally (cron/systemd) or via a future automation feature if enabled in your deployment.

Q: Can multiple Vulnera instances share one dataset?

- Yes. Place the dataset on a shared, fast, read-only capable volume. All instances should reference the same path. Coordinate updates carefully.

Q: How do I verify the dataset is being used?

- Run an analysis for a package known to have CVEs in NVD. Inspect Vulnera logs and responses for NVD-sourced references/IDs alongside OSV.

---

References:

- NVD (NIST): public JSON data feeds (consult official website for URLs and terms).
- nvd_cve crate: use its CLI and documentation to initialize and update the local dataset.
- Vulnera configuration: environment variable overrides using the VULNERA**SECTION**FIELD pattern.
