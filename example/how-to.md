# Backup + restore how-to (example)

This walks through running the Scrapligo tool against a containerlab
topology using the `sp-mv.clab.yaml` layout.

## 1) Deploy the lab
```bash
clab deploy -t sp-mv.clab.yaml --reconfigure
```

## 2) Run a backup (container)
```bash
docker run --rm -t --user 0 \
  --env-file "$PWD/.env.nck" \
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  ghcr.io/asadarafat/ne-config-kit:latest \
  --backup \
  --lab /clab/sp-mv.clab.yaml \
  --inventory /clab/clab-nokia-sp-mv/ansible-inventory.yml \
  --out /backups
```

Results:
- `startup-configs/<node>.txt` for XR/vMX/SROS
- `startup-configs/<node>.json` for SRL

## 3) Restore
```bash
docker run --rm -t --user 0 \
  --env-file "$PWD/.env.nck" \
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  ghcr.io/asadarafat/ne-config-kit:latest \
  --restore \
  --lab /clab/sp-mv.clab.yaml \
  --inventory /clab/clab-nokia-sp-mv/ansible-inventory.yml \
  --out /backups
```

## 4) Cisco-only validation (R02-cisco)
Backup:
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
  --only R02-cisco
```

Restore:
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

## Credentials
Store credentials in a local env file (do not commit it):
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

## Cleanup
```bash
clab destroy -t sp-mv.clab.yaml
```
