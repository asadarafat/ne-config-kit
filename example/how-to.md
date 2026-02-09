# Backup + restore how-to (example)

This walks through running the Scrapligo tool against the example
containerlab topology.

## 1) Deploy the lab
```
clab deploy -t example/clab-topo.clab.yml --reconfigure
```

## 2) Run a backup (container)
```
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/backups" \
  ne-config-kit:local \
  --backup --lab /clab/clab-topo.clab.yml --out /backups
```

Results:
- `backups/<node>.txt` for XR/vMX/SROS
- `backups/<node>.json` for SRL

## 3) Restore
```
docker run --rm -t \
  -v "$PWD/example:/clab:ro" \
  -v "$PWD/backups:/backups" \
  ne-config-kit:local \
  --restore --lab /clab/clab-topo.clab.yml --out /backups
```

## Credentials
Override defaults with env vars:
```
-e CISCO_USERNAME=clab -e CISCO_PASSWORD=clab@123 \
-e JUNIPER_USERNAME=admin -e JUNIPER_PASSWORD=admin@123 \
-e NOKIA_SROS_USERNAME=admin -e NOKIA_SROS_PASSWORD=admin \
-e NOKIA_SRL_USERNAME=admin -e NOKIA_SRL_PASSWORD='NokiaSrl1!'
```

## Cleanup
```
clab destroy -t example/clab-topo.clab.yml
```
