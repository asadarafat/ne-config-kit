# common role

This role provides the core backup, restore, and audit tasks for ne-config-kit.
It is intentionally vendor-agnostic and relies on Ansible connection plugins
and network modules to interact with devices.

## Tasks
- `backup.yml` pulls the running configuration, normalizes volatile lines, and
  writes `backups/<hostname>/running.conf` on the control node.
- `restore.yml` pushes `backups/<hostname>/running.conf` to the device and
  verifies post-restore state using the audit workflow.
- `audit.yml` compares live config to Git-stored config and fails on drift.
## Transport tasks
- HTTP API: `backup_httpapi.yml` / `restore_httpapi.yml`
- SCP: `backup_scp.yml` / `restore_scp.yml`

## Key variables (group_vars/routers/defaults.yml)
- `backup_transport`: `cli`, `netconf`, `httpapi`, or `scp`
- `backup_command`: CLI command for running config (CLI transport)
- `cli_restore_method`: `cli_config` or `line_by_line` for CLI restores
- `cli_restore_pre_commands` / `cli_restore_post_commands`: commands for line-by-line restores
- `backup_root` / `backup_filename`: backup location and file name
- `normalize_patterns`: regexes to strip volatile lines
- `httpapi_*`: generic REST/RESTCONF settings for HTTP API transport
- `scp_*`: SCP settings for file-based backup/restore

## Safety notes
- No Git operations are performed by the role.
- Restore verification can be disabled via `restore_verify: false`.
- Audit failures are intentional and signal drift.
