# Architecture

## Overview
ne-config-kit is a Git-first configuration management toolkit built on Ansible.
There is no daemon, controller, or database. The Git repository is the source
of truth, and Ansible playbooks are the execution engine.

## GitOps-style flow
1. **Backup (pull):** Collect running configuration from devices and normalize
   volatile lines.
2. **Version (Git):** Review and commit config changes in Git.
3. **Audit (compare):** Compare live device state to Git-stored configs and
   report drift.
4. **Restore (push):** Apply Git-stored config back to the device when needed.

```
device -> backup -> backups/<host>/running.conf -> Git
   ^                                              |
   |                                              v
restore <-------------------------------------- audit
```

## Execution model
- Ansible connects to devices using `network_cli`, `netconf`, or `httpapi`.
- Backup and audit run read-only operations on devices.
- Restore is an explicit, user-driven action and is always opt-in.
- All files are text-based to remain diff-friendly in Git.

## Separation of concerns
- **Repo:** Playbooks, roles, inventories, and backups live in Git.
- **Runtime:** Credentials and runtime state are provided at execution time
  (Vault, SSH keys, or environment variables).
- **Container:** The container image is a thin Ansible runtime and does not
  embed inventories, credentials, or backups.
