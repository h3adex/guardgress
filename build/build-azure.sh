#!/bin/bash

if [ -n "$DEBUG" ]; then
	set -x
fi

set -o errexit
set -o nounset
set -o pipefail

export TAG=latest
DEV_IMAGE=h3adex/guardgress:${TAG}
PLATFORM=linux/amd64
ACR_REGISTRY=guardgress.azurecr.io
DIR=$(cd $(dirname "${BASH_SOURCE}") && pwd -P)

echo "[dev-env] login docker registry ${DEV_IMAGE}"
echo "az acr login --name ${ACR_REGISTRY}"
az acr login --name "${ACR_REGISTRY}"

echo "[dev-env] cloud azure build ${DEV_IMAGE}"
echo "az acr build --image "${DEV_IMAGE}" --registry "${ACR_REGISTRY}" --file Dockerfile ."
az acr build --image "${DEV_IMAGE}" --registry "${ACR_REGISTRY}" --file Dockerfile .


#IMPORTANT: I prefer building in the cloud rather than local since I am developing on Mac

#echo "[dev-env] building image ${DEV_IMAGE}"
#echo "docker build --platform=${PLATFORM} -t ${DEV_IMAGE} ."
#docker build --platform=${PLATFORM} -t "${DEV_IMAGE}" .


#echo "[dev-env] pushing image ${DEV_IMAGE}"
#echo "docker tag ${DEV_IMAGE} ${ACR_REGISTRY}/${DEV_IMAGE}"
#docker tag ${DEV_IMAGE} ${ACR_REGISTRY}/${DEV_IMAGE}
#echo "docker push ${ACR_REGISTRY}/${DEV_IMAGE}"
#docker push ${ACR_REGISTRY}/${DEV_IMAGE}
