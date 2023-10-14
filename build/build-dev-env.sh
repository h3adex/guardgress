#!/bin/bash

if [ -n "$DEBUG" ]; then
	set -x
fi

set -o errexit
set -o nounset
set -o pipefail

export K8S_VERSION=${K8S_VERSION:-v1.26.3@sha256:61b92f38dff6ccc29969e7aa154d34e38b89443af1a2c14e6cfbd2df6419c66f}
export TAG=1.0.0-dev
DEV_IMAGE=phalanx:${TAG}
INGRESS_DEV_CLUSTER_NAME="phalanx-dev-cluster"
DIR=$(cd $(dirname "${BASH_SOURCE}") && pwd -P)

if ! command -v kind &> /dev/null; then
  echo "kind is not installed"
  echo "Use a package manager (i.e 'brew install kind') or visit the official site https://kind.sigs.k8s.io"
  exit 1
fi

if ! command -v kubectl &> /dev/null; then
  echo "Please install kubectl 1.24.0 or higher"
  exit 1
fi

if ! command -v helm &> /dev/null; then
  echo "Please install helm"
  exit 1
fi

echo "[dev-env] building image ${DEV_IMAGE}"
echo "docker build -t ${DEV_IMAGE} ."
docker build -t "${DEV_IMAGE}" .

if ! kind get clusters -q | grep -q ${INGRESS_DEV_CLUSTER_NAME}; then
  echo "[dev-env] creating Kubernetes cluster with kind"
  kind create cluster --name ${INGRESS_DEV_CLUSTER_NAME} --image "kindest/node:${K8S_VERSION}" --config ${DIR}/kind.yaml
else
  echo "[dev-env] using existing Kubernetes kind cluster"
fi

if kubectl config get-contexts -o name | grep -q "${INGRESS_DEV_CLUSTER_NAME}"; then
    kubectl config use-context "kind-${INGRESS_DEV_CLUSTER_NAME}"
else
    echo "[dev-env] Unable to set kubectl config for the kind cluster"
    exit 1
fi

echo "[dev-env] copying docker images to cluster..."
kind load docker-image --name="${INGRESS_DEV_CLUSTER_NAME}" "${DEV_IMAGE}"

echo "[dev-env] Generating new TLS secret"
if [ ! -f "bin/tls.key" ] || [ ! -f "bin/tls.crt" ]; then
    mkdir -p bin
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout bin/tls.key -out bin/tls.crt
    kubectl create secret tls ingress-tls --key bin/tls.key --cert bin/tls.crt
else
    echo "[dev-env] TLS secret files already exist. Skipping generation."
fi


if ! helm ls | grep -q whoami; then
    echo "[dev-env] Installing whoami test service with helm"
    # Create a separate directory for values.yaml to keep things organized
    mkdir -p bin/values
    cat > bin/values/whoami.yaml <<EOF
ingress:
  enabled: true
  ingressClassName: "phalanx"
  pathType: ImplementationSpecific
  annotations: {}
  hosts:
    - host: whoami.local
      paths:
        - /
  tls:
    - secretName: ingress-tls
      hosts:
        - whoami.local
EOF
    helm repo add cowboysysop https://cowboysysop.github.io/charts/
    helm install whoami cowboysysop/whoami --version 5.1.0 -f bin/values/whoami.yaml
else
    echo "[dev-env] whoami is already installed. Skipping installation."
fi

echo "[dev-env] Deploying local ingress controller"
cat <<EOF > bin/phalanx.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: phalanx
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["services","secrets"]
  verbs: ["get", "watch", "list"]
- apiGroups: ["extensions","networking.k8s.io"]
  resources: ["ingresses",]
  verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pod-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: phalanx
  namespace: default
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: phalanx
  name: phalanx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: phalanx
  strategy: {}
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: phalanx
    spec:
      serviceAccountName: phalanx
      containers:
      - image: docker.io/phalanx:${TAG}
        name: phalanx
        ports:
        - containerPort: 443
          name: https
          protocol: TCP
        - containerPort: 80
          name: http
          protocol: TCP
        resources: {}
---
apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    app: phalanx
  name: phalanx
spec:
  type: NodePort
  ports:
  - port: 443
    name: https
    protocol: TCP
    targetPort: 443
  - port: 80
    name: http
    protocol: TCP
    targetPort: 80
  selector:
    app: phalanx
status:
  loadBalancer: {}
EOF

kubectl delete -f bin/phalanx.yaml --ignore-not-found=true
kubectl apply -f bin/phalanx.yaml

echo "Kubernetes cluster ready and ingress listening on localhost using ports 80 and 443"
echo "To delete the dev cluster, execute: 'kind delete cluster --name phalanx-dev-cluster'"
