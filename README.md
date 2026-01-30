# ne-config-kit

ne-config-kit is an open-source NetDevOps toolkit for backing up, restoring,
and auditing network configurations using Ansible as the execution engine and
Git as the source of truth.

## Purpose and scope
- Git-based network configuration backup
- Deterministic restore and rollback
- Drift detection and audit reporting
- Text-only configs for clean diffs
- Works in labs (containerlab) and real networks
- Vendor-agnostic and automation-first

## Non-goals
- No GUI
- No database
- No scheduler
- No embedded Git operations
- No dependency on Oxidized, RANCID, or NMS systems

## Repository layout
```
inventories/
group_vars/
playbooks/
roles/
backups/
docs/
```

## Git + Ansible workflow
1. **Backup:** Pull running configs from devices.
2. **Review:** Inspect changes and commit to Git.
3. **Audit:** Compare live state with Git-stored config.
4. **Restore:** Push known-good config back to devices (explicit action).

## Quick start (local)
```
export ANSIBLE_NET_USERNAME="netops"
export ANSIBLE_NET_PASSWORD="***"

ansible-playbook -i inventories/lab.yml playbooks/backup.yml
ansible-playbook -i inventories/lab.yml playbooks/audit.yml
ansible-playbook -i inventories/lab.yml playbooks/restore.yml --check
```

## Restore warning
Restore is destructive by nature. Always run `--check` and `playbooks/audit.yml`
first. Do not run restore during unknown network conditions.

## Container usage model
The container image is a thin Ansible runtime. It does **not** include
inventories, credentials, or backups. You must mount your repo and provide
credentials at runtime.

Example:
```
docker run --rm -t \
  -v "$PWD:/work" \
  -v "$HOME/.ssh:/home/ansible/.ssh:ro" \
  -w /work \
  ghcr.io/<owner>/ne-config-kit:latest \
  -i inventories/lab.yml playbooks/backup.yml
```

## Security model
- Credentials are never stored in plaintext.
- Use Ansible Vault (`group_vars/routers/vault.yml`) for encrypted secrets.
- Environment variables are supported for CI/CD.
- Backups are sensitive data; restrict repo access.

See `docs/security.md` for details.

## Documentation
- `docs/architecture.md` - GitOps-style flow and execution model
- `docs/security.md` - credential handling and threat model

## License
MIT (see `LICENSE`).
