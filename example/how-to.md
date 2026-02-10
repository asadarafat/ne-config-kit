# Backup + restore how-to (example)

This walks through running the Scrapligo tool against a containerlab
topology using the `sp-mv.clab.yaml` layout.

## 1) Deploy the lab
```
clab deploy -t sp-mv.clab.yaml --reconfigure
```

## 2) Run a backup (container)
```
docker run --rm -t --user 0 \
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  -e CISCO_USERNAME=clab -e CISCO_PASSWORD='clab@123' \
  -e JUNIPER_USERNAME=admin -e JUNIPER_PASSWORD='admin@123' \
  -e NOKIA_SROS_USERNAME=admin -e NOKIA_SROS_PASSWORD='NokiaSros1!' \
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
```
docker run --rm -t --user 0 \
  -v "$PWD:/clab:ro" \
  -v "$PWD/startup-configs:/backups" \
  -e CISCO_USERNAME=clab -e CISCO_PASSWORD='clab@123' \
  -e JUNIPER_USERNAME=admin -e JUNIPER_PASSWORD='admin@123' \
  -e NOKIA_SROS_USERNAME=admin -e NOKIA_SROS_PASSWORD='NokiaSros1!' \
  -e NOKIA_SRL_USERNAME=admin -e NOKIA_SRL_PASSWORD='NokiaSrl1!' \
  ghcr.io/asadarafat/ne-config-kit:latest \
  --restore \
  --timeout 10m \
  --only R04-nokia \
  --lab /clab/sp-mv.clab.yaml \
  --inventory /clab/clab-nokia-sp-mv/ansible-inventory.yml \
  --out /backups
```

## Credentials
Override defaults with env vars:
```
-e CISCO_USERNAME=clab -e CISCO_PASSWORD=clab@123 \
-e JUNIPER_USERNAME=admin -e JUNIPER_PASSWORD=admin@123 \
-e NOKIA_SROS_USERNAME=admin -e NOKIA_SROS_PASSWORD='NokiaSros1!' \
-e NOKIA_SRL_USERNAME=admin -e NOKIA_SRL_PASSWORD='NokiaSrl1!'
```

## Cleanup
```
clab destroy -t sp-mv.clab.yaml
```
