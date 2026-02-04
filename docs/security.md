# Security model

## Credential handling
- **Ansible Vault:** Copy `image/ansible-config/group_vars/routers/vault.example.yml` to
  `image/ansible-config/group_vars/routers/vault.yml`, encrypt it with `ansible-vault`,
  and mount/provide it at runtime.
- **Environment variables:** `ANSIBLE_NET_USERNAME` and `ANSIBLE_NET_PASSWORD`
  are supported for CI/CD and ephemeral usage.
- **SSH keys:** `ANSIBLE_NET_SSH_KEY` can be used for key-based authentication.
- **Plaintext labs:** `example/nck-config.yaml` supports plaintext credentials for lab use.

## Backups are sensitive
Device configurations often include passwords, SNMP communities, keys, and
network topology details. Treat the `backups/` directory as sensitive data:
- Restrict access to the repo and CI logs.
- Use encrypted disks or a private Git host.
- Rotate credentials if exposure is suspected.

## Threat model (non-exhaustive)
- **Repo compromise:** An attacker with repo access may obtain configs.
- **CI exposure:** Improperly scoped CI logs can leak configs or secrets.
- **Misuse of restore:** Pushing an incorrect config can cause outages.

## Operational safety
- Restore is destructive by nature. Always run `restore --check`
  and `audit` before applying changes.
- Audit exits non-zero on drift to make CI/CD failures explicit.
- The container image embeds the Ansible workspace only. Inventories, credentials,
  and backups are provided at runtime (via `/clab` and `nck-config.yaml`).
