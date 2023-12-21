# Guardgress
![Tests](https://github.com/h3adex/guardgress/actions/workflows/test-go-code.yaml/badge.svg)
![Vulnerability Scan](https://github.com/h3adex/guardgress/actions/workflows/vulnerability-scan.yaml/badge.svg)
![Docker](https://github.com/h3adex/guardgress/actions/workflows/publish-to-docker.yaml/badge.svg)
![Go Report Card](https://goreportcard.com/badge/github.com/h3adex/guardgress)
![Go Version](https://img.shields.io/badge/go-1.21.5-blue)

Guardgress showcases a Web Application Firewall (WAF) integration within 
a Kubernetes Ingress Controller.

## Features
- [x] User-Agent Filtering: Blacklist/Whitelist with strings or regular expressions.
- [x] TLS Fingerprint Filtering: Whitelist/Blacklist requests based on ``Ja3, Ja3-Hash, Ja3n, Ja4, Ja4h`` fingerprints.
- [x] Request Header Enrichment: Add ``Ja3, Ja3-Hash, Ja3n, Ja4, Ja4h`` tls-fingerprints to the request header.
- [x] IP-Based Rate Limiting: Throttle requests originating from IP Addresses.
- [x] Redis Integration: Utilize Redis as a backend to store and manage rate limiting information efficiently.
- [x] SSL Redirection Enforcement: Ensure SSL connection by enforcing HTTPS through redirection.
- [x] Helm Chart Installation: Package the application as a Helm Chart for convenient and scalable deployment.
- [x] Integrated Prometheus Metrics and Health Check Server for monitoring and reliability


## Usage

The following table outlines the annotations available for the Guardgress Ingress Controller. These annotations can be used to control access, apply security measures, and configure rate limiting on Ingress API Objects.

| Annotation                              | Description                                                                             | Details                                                     | Example Configuration                                                                                                                           |
|-----------------------------------------|-----------------------------------------------------------------------------------------|-------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `guardgress/user-agent-whitelist`       | Limits access to specific User-Agents. Whitelist takes precedence over the blacklist.   | Comma-separated values.                                     | [User-Agent Whitelist and Blacklist](k8s/examples/ingress-ua-block-white-and-blacklist.yaml)                                                    |
| `guardgress/user-agent-blacklist`       | Blocks requests from particular User-Agents.                                            | Comma-separated values.                                     | [User-Agent Whitelist and Blacklist](k8s/examples/ingress-ua-block-white-and-blacklist.yaml)                                                    |
| `guardgress/tls-fingerprint-whitelist`  | Limits access based on TLS Fingerprints. Whitelist takes precedence over the blacklist. | `Ja3`, `Ja3-Hash`, `Ja3n`, `Ja4`, `Ja4h` - comma-separated. | [TLS Fingerprint Whitelist and Blacklist](k8s/examples/ingress-tls-block-white-and-blacklist.yaml)                                              |
| `guardgress/tls-fingerprint-blacklist`  | Restricts requests from specific TLS Fingerprints.                                      | `Ja3`, `Ja3-Hash`, `Ja3n`, `Ja4`, `Ja4h` - comma-separated. | [TLS Fingerprint Whitelist and Blacklist](k8s/examples/ingress-tls-block-white-and-blacklist.yaml)                                              |
| `guardgress/add-tls-fingerprint-header` | Adds TLS fingerprint/hashes to the request header.                                      | `Ja3`, `Ja3-Hash`, `Ja3n`, `Ja4`, `Ja4h`.                   | [Add TLS Header](k8s/examples/ingress-add-tls-header.yaml)                                                                                      |
| `guardgress/force-ssl-redirect`         | Forces SSL Redirection. Useful with a TLS certificate.                                  |                                                             | [Force SSL Redirect](k8s/examples/ingress-force-ssl-redirect.yaml)                                                                              |
| `guardgress/limit-ip-whitelist`         | Whitelists IP addresses for rate limiting.                                              |                                                             | [Real World Example](k8s/examples/ingress-real-world-example.yaml)                                                                              |
| `guardgress/limit-path-whitelist`       | Whitelists Paths for rate limiting.                                                     | Exempt specific paths from rate limiting.                   | [Real World Example](k8s/examples/ingress-real-world-example.yaml)                                                                              |
| `guardgress/limit-redis-store-url`      | Defines the URL of the Redis store for rate limiting.                                   | Default is in-memory store. Essential for HA mode.          | [Rate Limiting with Redis](k8s/examples/ingress-limit-period-with-redis.yaml)                                                                   |
| `guardgress/limit-period`               | Sets the rate limit period.                                                             | Format: `[number]-[S/M/H/D]` (Second/Minute/Hour/Day).      | See [Rate Limiting](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip) |

This Ingress Controller watches Ingress Resources with the `ingressClassName` set to "guardgress" or with no `ingressClassName` set at all.

## Installation

### With Helm
```shell
helm repo add guardgress https://h3adex.github.io/guardgress
helm repo update
helm install guardgress guardgress/guardgress-ingress-controller --namespace guardgress --create-namespace
```

### With K8s Manifests
```shell
git clone https://github.com/h3adex/guardgress
# Creates Namespace,SA,CRB,CR,Deployment,Service(LoadBalancer)
kubectl apply -f k8s/guardgress-deployment-svc.yaml
# Creates HPA
kubectl apply -f k8s/guardgress-deployment-hpa.yaml
```

Once installed, you can create ingress objects with the annotations described above. Examples
are located here: [k8s/examples](k8s/examples).

## Known Limitations
- Guardgress currently does not fully support certain functionalities provided by the Ingress API Object.
- The existence of a healthz route might cause conflicts for users intending to reverse proxy to this route.
- We ought to transition to Custom Resource Definitions (CRD) to store configuration information instead of relying solely on annotations. Presently, certain annotations, particularly those containing commas, aren't parsed accurately for user-agent configurations.

## Development
```sh
# deploy to local kind cluster
make dev kind
# build image and push to azure registry
make dev azure
```
This command facilitates container building and controller deployment on a kind cluster.
I've successfully tested the functionality of this ingress-controller on an AKS cluster,
leveraging cert-manager for added support.

Further information on how to set up my local test environment 
can be found in [here](build/README.md).

## Ideas
Don't hesitate to open an issue or pull request with your suggestions or ideas
- [ ] Proxy Connection Identification: Implement a method described in [this paper](https://dl.acm.org/doi/abs/10.1007/978-3-031-21280-2_18) to identify connections through proxies.

## License
This project operates under the MIT License. Refer to the [LICENSE](LICENSE) file for details.

## Disclaimer
This project is currently in the development phase and is not recommended for production use. 
It is a Proof of Concept.

## Acknowledgments
- [k8s-simple-ingress-controller](https://github.com/calebdoxsey/kubernetes-simple-ingress-controller) provided a starting point for this project.
- [ja3rp](https://github.com/sleeyax/ja3rp) inspired the creation of this project.
- [fp](https://github.com/gospider007/fp) aided in obtaining client fingerprint information.
- [limiter](https://github.com/ulule/limiter/) provided the rate limiting functionality.