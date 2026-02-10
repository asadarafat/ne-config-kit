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
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  -e CISCO_USERNAME=clab -e CISCO_PASSWORD='clab@123' \
  -e JUNIPER_USERNAME=admin -e JUNIPER_PASSWORD='admin@123' \
  -e NOKIA_SROS_USERNAME=admin -e NOKIA_SROS_PASSWORD=admin \
  -e NOKIA_SRL_USERNAME=admin -e NOKIA_SRL_PASSWORD='NokiaSrl1!' \
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
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  -e CISCO_USERNAME=clab -e CISCO_PASSWORD='clab@123' \
  -e JUNIPER_USERNAME=admin -e JUNIPER_PASSWORD='admin@123' \
  -e NOKIA_SROS_USERNAME=admin -e NOKIA_SROS_PASSWORD=admin \
  -e NOKIA_SRL_USERNAME=admin -e NOKIA_SRL_PASSWORD='NokiaSrl1!' \
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
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  -e CISCO_USERNAME=clab -e CISCO_PASSWORD='clab@123' \
  -e JUNIPER_USERNAME=admin -e JUNIPER_PASSWORD='admin@123' \
  -e NOKIA_SROS_USERNAME=admin -e NOKIA_SROS_PASSWORD=admin \
  -e NOKIA_SRL_USERNAME=admin -e NOKIA_SRL_PASSWORD='NokiaSrl1!' \
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
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  -e CISCO_USERNAME=clab -e CISCO_PASSWORD='clab@123' \
  -e JUNIPER_USERNAME=admin -e JUNIPER_PASSWORD='admin@123' \
  -e NOKIA_SROS_USERNAME=admin -e NOKIA_SROS_PASSWORD=admin \
  -e NOKIA_SRL_USERNAME=admin -e NOKIA_SRL_PASSWORD='NokiaSrl1!' \
  ghcr.io/asadarafat/ne-config-kit:latest \
  --restore \
  --lab /clab/sp-mv.clab.yaml \
  --inventory /clab/clab-nokia-sp-mv/ansible-inventory.yml \
  --out /backups \
  --debug \
  --only R02-cisco
```

## Credentials
Override defaults with env vars:
```bash
-e CISCO_USERNAME=clab -e CISCO_PASSWORD=clab@123 \
-e JUNIPER_USERNAME=admin -e JUNIPER_PASSWORD=admin@123 \
-e NOKIA_SROS_USERNAME=admin -e NOKIA_SROS_PASSWORD=admin \
-e NOKIA_SRL_USERNAME=admin -e NOKIA_SRL_PASSWORD='NokiaSrl1!'
```

## Cleanup
```bash
clab destroy -t sp-mv.clab.yaml
```
