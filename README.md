# ne-config-kit

ne-config-kit is an open-source NetDevOps toolkit for backing up, restoring,
and managing the configuration state of network elements using Ansible and Git.

It is vendor-agnostic, automation-first, and designed to work equally well
in labs (containerlab) and real networks.

## What this is
- Git-based network configuration backup
- Deterministic restore and rollback
- Foundation for drift detection and desired-state workflows
- Built with Ansible, not a custom daemon or controller

## What this is NOT
- Not a full NMS or controller
- Not a UI-driven product
- Not tied to a single vendor or NOS

## Core principles
- Git is the source of truth
- Automation over polling
- Explicit intent over implicit state
- Simple building blocks, composable workflows

## Supported automation models
- Backup (pull)
- Restore (push)
- Audit / drift detection
- Desired-state enforcement (optional)

## Repository layout
```
inventories/
group_vars/
host_vars/
playbooks/
roles/
backups/
```

## Quick start
1. Clone the repo
2. Define your inventory
3. Store credentials securely (Ansible Vault or SSH keys)
4. Run the backup playbook
5. Commit configs to Git

## Security
Credentials are never stored in plaintext.
Ansible Vault, SSH keys, or external secret managers are supported.

## Use cases
- Lab automation (containerlab)
- Pre/post change validation
- Disaster recovery
- Compliance audits
- GitOps-style network workflows

## Roadmap
- Config normalization
- Drift detection reports
- gNMI / NETCONF-first workflows
- CI/CD examples
