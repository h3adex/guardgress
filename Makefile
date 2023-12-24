K8S_VERSION ?= v1.29.0
TAG ?= 1.0.0-dev
DEV_IMAGE ?= guardgress:${TAG}
DEV_CLUSTER ?= guardgress-dev-cluster
PLATFORM ?= linux/amd64
ACR_REGISTRY ?= guardgress.azurecr.io
DIR := $(shell pwd -P)/build

.PHONY: all setup create-cluster build-image configure-kubectl load-image deploy clean help

deploy-kind: setup create-cluster build-image configure-kubectl load-image deploy

setup:
	@command -v kind >/dev/null 2>&1 || { echo "kind not installed. Install via package manager or https://kind.sigs.k8s.io"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "kubectl not installed. Install 1.24.0 or higher"; exit 1; }
	@command -v helm >/dev/null 2>&1 || { echo "helm not installed. Install via package manager"; exit 1; }

build-image:
	@echo "[dev-env] building image ${DEV_IMAGE}"
	docker build -t "${DEV_IMAGE}" .

create-cluster:
	@if ! kind get clusters -q | grep -q ${DEV_CLUSTER}; then \
		echo "[dev-env] creating Kubernetes cluster with kind"; \
		kind create cluster --name ${DEV_CLUSTER} --image "kindest/node:${K8S_VERSION}" --config ${DIR}/kind.yaml; \
	else \
		echo "[dev-env] using existing Kubernetes kind cluster"; \
	fi

configure-kubectl:
	@if kubectl config get-contexts -o name | grep -q "${DEV_CLUSTER}"; then \
		echo "kubectl config use-context kind-${DEV_CLUSTER}"; \
		kubectl config use-context "kind-${DEV_CLUSTER}"; \
	else \
		echo "[dev-env] Unable to set kubectl config for the kind cluster"; \
		exit 1; \
	fi

load-image:
	@echo "[dev-env] copying docker images to cluster..."
	kind load docker-image --name="${DEV_CLUSTER}" "${DEV_IMAGE}"

deploy:
	@if [ ! -f "bin/tls.key" ] || [ ! -f "bin/tls.crt" ]; then \
		mkdir -p bin; \
		openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout bin/tls.key -out bin/tls.crt; \
		kubectl create secret tls ingress-tls --key bin/tls.key --cert bin/tls.crt; \
	else \
		echo "[dev-env] TLS secret files already exist. Skipping generation."; \
	fi; \
	if ! helm ls | grep -q whoami; then \
		echo "[dev-env] Installing whoami helm chart"; \
		helm repo add cowboysysop https://cowboysysop.github.io/charts/; \
		helm install whoami cowboysysop/whoami --version 5.1.0; \
	else \
		echo "[dev-env] whoami is already installed. Skipping installation."; \
	fi; \
	if ! helm -n prometheus ls | grep -q prometheus; then \
		echo "[dev-env] Installing prometheus helm chart"; \
		helm repo add prometheus-community https://prometheus-community.github.io/helm-charts; \
		helm install prometheus prometheus-community/prometheus --version 25.8.2 -n prometheus --create-namespace; \
	else \
		echo "[dev-env] prometheus is already installed. Skipping installation."; \
	fi; \
	if ! helm -n grafana ls | grep -q grafana; then \
		echo "[dev-env] Installing grafana helm chart"; \
		helm repo add grafana https://grafana.github.io/helm-charts; \
		helm install grafana grafana/grafana -f ${DIR}/grafana-values.yaml --version 7.0.19 -n grafana --create-namespace; \
	else \
		echo "[dev-env] grafana is already installed. Skipping installation."; \
	fi; \
	kubectl delete -f ${DIR}/guardgress-kind.yaml --ignore-not-found=true; \
	kubectl apply -f ${DIR}/guardgress-kind.yaml; \
	echo "Kubernetes cluster ready and ingress listening on localhost using ports 80 and 443"

build-azure:
	echo "[dev-env] login docker registry ${DEV_IMAGE}"
	echo "az acr login --name ${ACR_REGISTRY}"
	az acr login --name "${ACR_REGISTRY}"

	echo "[dev-env] cloud azure build ${DEV_IMAGE}"
	echo "az acr build --image "${DEV_IMAGE}" --registry "${ACR_REGISTRY}" --file Dockerfile ."
	az acr build --image "${DEV_IMAGE}" --registry "${ACR_REGISTRY}" --file Dockerfile .

load-test:
	echo "GET https://0.0.0.0:443/" | vegeta attack -duration=5s -insecure -rate=100/1s -header="Host: whoami.local"

clean:
	@kind delete cluster --name ${DEV_CLUSTER}
	@echo "Cleaned up development environment."

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@echo "  all               - Run the complete development environment setup, including Kind cluster deployment and Azure image building."
	@echo "  setup             - Check and set up necessary dependencies (kind, kubectl, helm)."
	@echo "  build-image       - Build the Docker image using the provided Dockerfile. Image name: ${DEV_IMAGE}."
	@echo "  create-cluster    - Create a new Kind Kubernetes cluster if it doesn't exist, or use the existing cluster. Cluster name: ${DEV_CLUSTER}."
	@echo "  configure-kubectl - Set up kubectl to use the context of the Kind cluster named ${DEV_CLUSTER}."
	@echo "  load-image        - Load the built Docker image into the Kind Kubernetes cluster."
	@echo "  deploy-ingress    - Deploy ingress resources, including TLS setup and helm charts for 'whoami' and 'prometheus'."
	@echo "  build-azure       - Build and push the Docker image to Azure Container Registry. Registry: ${ACR_REGISTRY}."
	@echo "  clean             - Delete the Kind Kubernetes cluster and clean up the development environment."
	@echo ""
	@echo "Note: Modify variables (e.g., K8S_VERSION, TAG) in the Makefile or pass them as arguments to customize the build."
	@echo "Example: make build-image TAG=2.0.0"

