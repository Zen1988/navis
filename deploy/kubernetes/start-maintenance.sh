#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ! $1 =~ ^[a-z0-9][a-z0-9./:_@-]*$ ]]; then
  echo "Usage: bash $0 CLUSTER_ACCESSIBLE_IMAGE [ENV_FILE]" >&2
  exit 2
fi
image=$1
env_file=${2:-.env.maintenance}
namespace=${NAVIS_K8S_NAMESPACE:-navis}
backup_size=${NAVIS_BACKUP_SIZE:-5Gi}
if [[ ! $backup_size =~ ^[1-9][0-9]*Gi$ ]]; then
  echo 'NAVIS_BACKUP_SIZE must be a positive whole number of Gi, such as 5Gi.' >&2
  exit 2
fi

# Create the Secret once. An existing Secret is kept for the running workflow.
secret=$(kubectl get secret navis-maintenance-db -n "$namespace" --ignore-not-found -o name)
if [[ -z $secret ]]; then
  kubectl create secret generic navis-maintenance-db -n "$namespace" --from-env-file="$env_file"
fi
claim=$(kubectl get pvc navis-maintenance-backups -n "$namespace" --ignore-not-found -o name)
if [[ -z $claim ]]; then
  kubectl create -n "$namespace" -f - <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: navis-maintenance-backups
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: $backup_size
YAML
fi

pod=$(kubectl get pod navis-maintenance -n "$namespace" --ignore-not-found -o name)
if [[ -n $pod ]]; then
  current_image=$(kubectl get pod navis-maintenance -n "$namespace" -o jsonpath='{.spec.containers[?(@.name=="maintenance")].image}')
  if [[ $current_image != "$image" ]]; then
    echo 'The existing maintenance pod uses a different image. Finish any running maintenance before replacing it.' >&2
    exit 1
  fi
else
  kubectl create -n "$namespace" -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: navis-maintenance
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
  containers:
  - name: maintenance
    image: "$image"
    imagePullPolicy: IfNotPresent
    command: ["sleep", "infinity"]
    env:
    - name: NAVIS_DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: navis-maintenance-db
          key: NAVIS_DATABASE_URL
    volumeMounts:
    - name: backups
      mountPath: /backups
  volumes:
  - name: backups
    persistentVolumeClaim:
      claimName: navis-maintenance-backups
YAML
fi

if ! kubectl wait -n "$namespace" --for=condition=Ready pod/navis-maintenance --timeout=120s; then
  kubectl describe pod navis-maintenance -n "$namespace" | sed -n '/Events:/,$p'
  exit 1
fi
kubectl exec -n "$namespace" navis-maintenance -c maintenance -- \
  python -m navis_api.migrate plan
