# ne-config-kit

ne-config-kit is an open-source NetDevOps toolkit for backing up and restoring
network configurations using Scrapligo (Go) and Git as the source of truth.

## Purpose and scope
- Git-based network configuration backup
- Deterministic restore and rollback
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
tools/scrapligo-backup/
backup-restore.sh
docs/
```

## Quick start (Go)
Backup using a containerlab topology file:
```
go run ./tools/scrapligo-backup --backup \
  --lab example/clab-topo.clab.yml \
  --out backups
```

Restore:
```
go run ./tools/scrapligo-backup --restore \
  --lab example/clab-topo.clab.yml \
  --out backups
```

## Quick start (container)
Build locally:
```
docker build -t ne-config-kit:local .
```

Run backup:
```
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/backups" \
  ne-config-kit:local \
  --backup --lab /clab/clab-topo.clab.yml --out /backups
```

Restore:
```
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/backups" \
  ne-config-kit:local \
  --restore --lab /clab/clab-topo.clab.yml --out /backups
```

## Credentials
Credentials are supplied via environment variables. Defaults match the legacy
`backup-restore.sh` script:
- `CISCO_USERNAME`, `CISCO_PASSWORD` (default `clab` / `clab@123`)
- `JUNIPER_USERNAME`, `JUNIPER_PASSWORD` (default `admin` / `admin@123`)
- `NOKIA_SROS_USERNAME`, `NOKIA_SROS_PASSWORD` (default `admin` / `admin`)
- `NOKIA_SRL_USERNAME`, `NOKIA_SRL_PASSWORD` (default `admin` / `NokiaSrl1!`)

## Supported kinds
The Scrapligo tool reads `kind` and `mgmt-ipv4` from the containerlab topology.
Supported kinds:
- `vr-xrv9k` (Cisco XR)
- `vr-vmx` (Juniper vMX)
- `vr-sros` (Nokia SR OS)
- `srl` (Nokia SR Linux)

## Documentation
- `docs/architecture.md` - execution model and flow
- `docs/security.md` - credential handling and threat model

## License
MIT (see `LICENSE`).
