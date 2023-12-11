#!/bin/bash

if [ -n "$DEBUG" ]; then
	set -x
fi

set -o errexit
set -o nounset
set -o pipefail

export K8S_VERSION=${K8S_VERSION:-v1.26.3@sha256:61b92f38dff6ccc29969e7aa154d34e38b89443af1a2c14e6cfbd2df6419c66f}
export TAG=1.0.0-dev
DEV_IMAGE=guardgress:${TAG}
INGRESS_DEV_CLUSTER_NAME="guardgress-dev-cluster"
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
    helm repo add cowboysysop https://cowboysysop.github.io/charts/
    helm install whoami cowboysysop/whoami --version 5.1.0
else
    echo "[dev-env] whoami is already installed. Skipping installation."
fi

echo "[dev-env] Deploying local ingress controller"
cat <<EOF > bin/guardgress.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: guardgress-sa
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: guardgress-cr
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
  name: guardgress-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: guardgress-cr
subjects:
- kind: ServiceAccount
  name: guardgress-sa
  namespace: default
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: guardgress-ingress-controller
  namespace: default
  labels:
    app: guardgress-ingress-controller
spec:
  selector:
    matchLabels:
      app: guardgress-ingress-controller
  template:
    metadata:
      labels:
        app: guardgress-ingress-controller
    spec:
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      serviceAccountName: guardgress-sa
      containers:
        - image: docker.io/guardgress:1.0.0-dev
          name: guardgress-ingress-controller
          imagePullPolicy: Never
          env:
            - name: PORT
              value: "81"
            - name: TLS_PORT
              value: "444"
            - name: HOST
              value: "0.0.0.0"
            - name: GIN_MODE
              value: "release"
            - name: LOG_LEVEL
              value: "debug"
            - name: FORCE_LOCALHOST_CERT
              value: "true"
          readinessProbe:
            httpGet:
              path: /healthz
              port: 81
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 5
          livenessProbe:
            httpGet:
              path: /healthz
              port: 81
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 5
          ports:
            - name: http
              containerPort: 81
            - name: https
              containerPort: 444
          resources:
            limits:
              memory: 256Mi
            requests:
              cpu: 50m
              memory: 128Mi
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    guardgress/add-tls-fingerprint-header: "true"
    guardgress/limit-period: "10-S"
  name: whoami
  namespace: default
spec:
  ingressClassName: guardgress
  rules:
  - host: whoami.local
    http:
      paths:
      - backend:
          service:
            name: whoami
            port:
              number: 80
        path: /
        pathType: ImplementationSpecific
  tls:
  - hosts:
    - localhost
    secretName: ingress-tls
status:
  loadBalancer: {}
EOF

kubectl delete -f bin/guardgress.yaml --ignore-not-found=true
kubectl apply -f bin/guardgress.yaml

echo "Kubernetes cluster ready and ingress listening on localhost using ports 80 and 443"
echo "To delete the dev cluster, execute: 'kind delete cluster --name guardgress-dev-cluster'"
