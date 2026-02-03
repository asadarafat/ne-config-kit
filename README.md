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
1. Update `example/nck-config.yaml` (lab name, credentials, and backup path).
2. Deploy the lab and run NCK as a standalone container:
```
clab deploy -t example/clab-topo.clab.yml --reconfigure

docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/backups" \
  ghcr.io/<owner>/ne-config-kit:latest backup
```
Use `restore --check` or `audit` as needed.

## Tests
Run the regression test suite:
```
make test
```

## Restore warning
Restore is destructive by nature. Always run `restore --check` and `audit`
first. Do not run restore during unknown network conditions.

## Container usage model
The container image ships with the Ansible workspace baked in under `/work`.
Mount only runtime inputs (containerlab output + backups) and run the playbooks.

Example:
```
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/backups" \
  ghcr.io/<owner>/ne-config-kit:latest backup
```
Override the config path with `-e NCK_CONFIG=/clab/nck-config.yaml` or pass
extra Ansible flags after the command (for example `restore --check`).

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
