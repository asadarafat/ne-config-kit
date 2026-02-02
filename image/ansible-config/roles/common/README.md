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

## Key variables (group_vars/routers/defaults.yml)
- `backup_transport`: `cli`, `netconf`, or `httpapi`
- `backup_command`: CLI command for running config (CLI transport)
- `backup_root` / `backup_filename`: backup location and file name
- `normalize_patterns`: regexes to strip volatile lines
- `httpapi_*`: generic REST/RESTCONF settings for HTTP API transport

## Safety notes
- No Git operations are performed by the role.
- Restore verification can be disabled via `restore_verify: false`.
- Audit failures are intentional and signal drift.
