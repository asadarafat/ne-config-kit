# Backup + restore how-to (example)

This walks through running NCK as a standalone container against the example
containerlab topology.

## 1) Deploy the lab
```
clab deploy -t example/clab-topo.clab.yml --reconfigure
```

## 2) Update the config
Edit `example/nck-config.yaml` for your lab name, targets, and credentials.

Notes:
- `backup_filename_template` writes timestamped archives.
- `backup_filename` is the stable file used by audit/restore.

## 3) Run a backup
```
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/nck-backups" \
  ghcr.io/asadarafat/ne-config-kit:latest backup
```

Results:
- `nck-backups/<host>/running.conf` (stable)
- `nck-backups/<host>/<clab_lab_name>__<ne_name>__<time-stamp>.conf` (archive)

## 4) Dry-run restore
```
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/nck-backups" \
  ghcr.io/asadarafat/ne-config-kit:latest restore --check
```

## 5) Restore for real
```
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/nck-backups" \
  ghcr.io/asadarafat/ne-config-kit:latest restore
```

## Restoring a specific archive
Restore always reads `backup_filename`. To restore a timestamped archive, set
`backup_filename` to that archive name in `example/nck-config.yaml`, then run
`restore` again.

## Optional: custom config location
If you store the config elsewhere, pass:
```
-e NCK_CONFIG=/clab/nck-config.yaml
```

## Cleanup
```
clab destroy -t example/clab-topo.clab.yml
```
