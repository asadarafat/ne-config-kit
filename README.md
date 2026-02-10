# ne-config-kit

ne-config-kit is a NetDevOps toolkit for backing up and restoring network
configurations with Scrapligo (Go), focused on containerlab-style topologies.

## Purpose and scope
- Diff-friendly, version-control-ready configuration backups
- Deterministic restore and rollback workflows
- Works with lab topologies and inventory data
- Vendor-agnostic, automation-first CLI workflow

## Non-goals
- No GUI
- No database
- No scheduler
- No embedded Git operations
- No dependency on Oxidized, RANCID, or NMS systems

## Repository layout
```text
README.md
Makefile
Dockerfile
example/
tools/scrapligo-backup/
```

## Requirements
- Docker (required for running the tool and lint workflow)
- Go (optional, only for local source-based development/build)

## Quick start (container, hands-on)
1) Pull image:
```bash
docker pull ghcr.io/asadarafat/ne-config-kit:latest
```

2) Prepare local backup folder and credentials file:
```bash
mkdir -p startup-configs

cat > .env.nck <<'EOF'
CISCO_USERNAME=<set-me>
CISCO_PASSWORD=<set-me>
JUNIPER_USERNAME=<set-me>
JUNIPER_PASSWORD=<set-me>
NOKIA_SROS_USERNAME=<set-me>
NOKIA_SROS_PASSWORD=<set-me>
NOKIA_SRL_USERNAME=<set-me>
NOKIA_SRL_PASSWORD=<set-me>
EOF

chmod 600 .env.nck
```

3) Run backup:
```bash
docker run --rm -t --user 0 \
  --env-file "$PWD/.env.nck" \
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  ghcr.io/asadarafat/ne-config-kit:latest \
  --backup \
  --lab /clab/sp-mv.clab.yaml \
  --inventory /clab/clab-nokia-sp-mv/ansible-inventory.yml \
  --out /backups \
  --debug \
  --only R01-nokia
```

4) Run restore:
```bash
docker run --rm -t --user 0 \
  --env-file "$PWD/.env.nck" \
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  ghcr.io/asadarafat/ne-config-kit:latest \
  --restore \
  --lab /clab/sp-mv.clab.yaml \
  --inventory /clab/clab-nokia-sp-mv/ansible-inventory.yml \
  --out /backups \
  --debug \
  --only R02-cisco
```

## Flags explained
Docker flags:
- `--rm`: remove container after command exits.
- `-t`: allocate a TTY (cleaner CLI output).
- `--user 0`: run as root in container (useful for file permissions/SSH tooling).
- `--env-file "$PWD/.env.nck"`: load credentials from a local env file.
- `-v "$PWD:/clab:ro"`: mount current clab working directory as read-only input at `/clab`.
- `-v "$PWD/startup-configs:/backups"`: mount backup/restore files at `/backups`.
- `-e KEY=VALUE`: optional alternative to `--env-file` for ad-hoc overrides.

Tool flags:
- `--backup`: run backup flow.
- `--restore`: run restore flow.
- `--lab /clab/sp-mv.clab.yaml`: topology file path inside container.
- `--inventory /clab/clab-nokia-sp-mv/ansible-inventory.yml`: inventory fallback for `ansible_host`.
- `--out /backups`: output/input directory for config files.
- `--debug`: enable verbose logs (including Scrapli debug output).
- `--only R01-nokia` or `--only R02-cisco`: run operation only for selected node(s).
- `--skip-health`: optional, skip container health checks before execution.

## Credentials
Do not commit real credentials to Git.

If you did not create `.env.nck` in the hands-on section above, create it with:
```bash
cat > .env.nck <<'EOF'
CISCO_USERNAME=<set-me>
CISCO_PASSWORD=<set-me>
JUNIPER_USERNAME=<set-me>
JUNIPER_PASSWORD=<set-me>
NOKIA_SROS_USERNAME=<set-me>
NOKIA_SROS_PASSWORD=<set-me>
NOKIA_SRL_USERNAME=<set-me>
NOKIA_SRL_PASSWORD=<set-me>
EOF
chmod 600 .env.nck
```

Variables used by the tool:
- `CISCO_USERNAME`, `CISCO_PASSWORD`
- `JUNIPER_USERNAME`, `JUNIPER_PASSWORD`
- `NOKIA_SROS_USERNAME`, `NOKIA_SROS_PASSWORD`
- `NOKIA_SRL_USERNAME`, `NOKIA_SRL_PASSWORD`

Note:
- The binary has built-in lab defaults for convenience, but for secure usage you should always set credentials explicitly via env file or environment variables.

## Supported kinds
The tool reads `kind` and `mgmt-ipv4` from topology (with inventory fallback).
- `vr-xrv9k` (Cisco XR)
- `vr-vmx` (Juniper vMX)
- `vr-sros` (Nokia SR OS)
- `srl` (Nokia SR Linux)

## Restore behavior summary
- Cisco XR: uploads config to `/misc/scratch/<node>.txt`, sanitizes timestamp
  banner lines, runs `load`, then `commit replace`.
- Juniper vMX: uploads to `/var/home/<user>/<node>.txt` (SCP with SFTP
  fallback), then applies `load set` or `load override` based on file content.
- Nokia SR OS: uploads config and applies `load full-replace` + `commit`.
- Nokia SR Linux: uploads JSON and applies `load file ... auto-commit`.

## Development
Build binary:
```bash
make build
```

Install/update tooling images:
```bash
make tools
```

Run strict lint:
```bash
make lint
```

Auto-fix lintable issues:
```bash
make lint-fix
```

Remove local tools directory:
```bash
make clean-tools
```

Notes:
- Linting uses `golangci/golangci-lint:v2.8.0` in Docker.
- Config is enforced from `.golangci.yml`.

## Additional guide
- `example/how-to.md`: end-to-end backup/restore walkthrough

## License
MIT (see `LICENSE`).
