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
example/
image/ansible-config/
backups/
docs/
```

## Git + Ansible workflow
1. **Backup:** Pull running configs from devices.
2. **Review:** Inspect changes and commit to Git.
3. **Audit:** Compare live state with Git-stored config.
4. **Restore:** Push known-good config back to devices (explicit action).

## Quick start (containerlab)
1. Update `example/nck-config.yaml` with credentials and backup path.
2. Deploy the lab and run a backup from the runner container:
```
clab deploy -t example/clab-topo.clab.yml --reconfigure

docker exec -w /work clab-ne-config-kit-example-nck \
  ansible-playbook -i /clab/clab-ne-config-kit-example/ansible-inventory.yml \
  playbooks/backup.yml --limit clab-ne-config-kit-example-srl1
```

## Restore warning
Restore is destructive by nature. Always run `--check` and `playbooks/audit.yml`
first. Do not run restore during unknown network conditions.

## Container usage model
The container image ships with the Ansible workspace baked in under `/work`.
Mount only runtime inputs (containerlab output + backups) and run the playbooks.

Example:
```
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/backups" \
  ghcr.io/<owner>/ne-config-kit:latest \
  -i /clab/clab-ne-config-kit-example/ansible-inventory.yml playbooks/backup.yml \
  --limit clab-ne-config-kit-example-srl1
```

## Security model
- Credentials can be supplied via `nck-config.yaml` (plaintext for labs) or
  Ansible Vault (`image/ansible-config/group_vars/routers/vault.yml`) for encrypted secrets.
- Environment variables are supported for CI/CD.
- Backups are sensitive data; restrict repo access.

See `docs/security.md` for details.

## Documentation
- `docs/architecture.md` - GitOps-style flow and execution model
- `docs/security.md` - credential handling and threat model

## License
MIT (see `LICENSE`).
