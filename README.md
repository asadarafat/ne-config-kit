# ne-config-kit

ne-config-kit is a NetDevOps toolkit for backing up and restoring network
configurations with Scrapligo (Go), focused on containerlab-style topologies.

## Purpose and scope
- Git-friendly network configuration backup
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
- Docker (for container execution and lint tooling)
- Go (only required for local `go run`/`go build` workflows)

## Quick start (Go)
Backup:
```bash
go run ./tools/scrapligo-backup --backup \
  --lab example/clab-topo.clab.yml \
  --out backups
```

Restore:
```bash
go run ./tools/scrapligo-backup --restore \
  --lab example/clab-topo.clab.yml \
  --out backups
```

## Quick start (container)
Build locally:
```bash
docker build -t ne-config-kit:local .
```

Backup:
```bash
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/backups" \
  ne-config-kit:local \
  --backup \
  --lab /clab/clab-topo.clab.yml \
  --out /backups
```

Restore:
```bash
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/backups" \
  ne-config-kit:local \
  --restore \
  --lab /clab/clab-topo.clab.yml \
  --out /backups
```

## Common flags
- `--inventory <path>`: optional Ansible inventory file (ansible_host fallback)
- `--only <node1,node2>`: target subset of nodes
- `--debug`: enables verbose logs (including Scrapli debug output)
- `--skip-health`: skips container health checks

## Credentials
Set credentials via environment variables:
- `CISCO_USERNAME`, `CISCO_PASSWORD` (default `clab` / `clab@123`)
- `JUNIPER_USERNAME`, `JUNIPER_PASSWORD` (default `admin` / `admin@123`)
- `NOKIA_SROS_USERNAME`, `NOKIA_SROS_PASSWORD` (default `admin` / `admin`)
- `NOKIA_SRL_USERNAME`, `NOKIA_SRL_PASSWORD` (default `admin` / `NokiaSrl1!`)

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
