# Guardgress
![Tests](https://github.com/h3adex/guardgress/actions/workflows/test-go-code.yaml/badge.svg)
![Vulnerability Scan](https://github.com/h3adex/guardgress/actions/workflows/vulnerability-scan.yaml/badge.svg)
![Docker](https://github.com/h3adex/guardgress/actions/workflows/publish-to-docker.yaml/badge.svg)
![Go Report Card](https://goreportcard.com/badge/github.com/h3adex/guardgress)
![Go Version](https://img.shields.io/badge/go-1.22.0-blue)

Guardgress showcases a Web Application Firewall (WAF) integration within 
a Kubernetes Ingress Controller.

> [!CAUTION]
> This project is a Proof of Concept and is not recommended for production use.

## Features
- [x] User-Agent Filtering: Blacklist/Whitelist with strings or regular expressions.
- [x] TLS Fingerprint Filtering: Whitelist/Blacklist requests based on ``Ja3, Ja3-Hash, Ja3n, Ja4, Ja4h`` fingerprints.
- [x] Request Header Enrichment: Add ``Ja3, Ja3-Hash, Ja3n, Ja4, Ja4h`` tls-fingerprints to the request header.
- [x] IP-Based Rate Limiting: Throttle requests originating from IP Addresses.
- [x] Redis Integration: Utilize Redis as a backend to store and manage rate limiting information efficiently.
- [x] SSL Redirection Enforcement: Ensure SSL connection by enforcing HTTPS through redirection.
- [x] Configure Whitelisted IP Source Ranges: Define and apply a set of whitelisted IP ranges.
- [x] Helm Chart Installation: Package the application as a Helm Chart for convenient and scalable deployment.
- [x] Integrated Prometheus Metrics and Health Check Server for monitoring and reliability

## Usage

The following table outlines the annotations available for the Guardgress Ingress Controller.
These annotations can be used to control access, apply security measures, and configure rate 
limiting on Ingress API Objects.

| Annotation                              | Description                                                                                                    | Details                                                     | Example Configuration                                                                                                                       |
|-----------------------------------------|----------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `guardgress/user-agent-whitelist`       | Limits access to specific User-Agents. Whitelist takes precedence over the blacklist.                          | Comma-separated values.                                     | [User-Agent Whitelist and Blacklist](k8s/examples/ingress-ua-block-white-and-blacklist.yaml)                                                |
| `guardgress/user-agent-blacklist`       | Blocks requests from particular User-Agents.                                                                   | Comma-separated values.                                     | [User-Agent Whitelist and Blacklist](k8s/examples/ingress-ua-block-white-and-blacklist.yaml)                                                |
| `guardgress/tls-fingerprint-whitelist`  | Limits access based on TLS Fingerprints. Whitelist takes precedence over the blacklist.                        | `Ja3`, `Ja3-Hash`, `Ja3n`, `Ja4`, `Ja4h` - comma-separated. | [TLS Fingerprint Whitelist and Blacklist](k8s/examples/ingress-tls-block-white-and-blacklist.yaml)                                          |
| `guardgress/tls-fingerprint-blacklist`  | Restricts requests from specific TLS Fingerprints.                                                             | `Ja3`, `Ja3-Hash`, `Ja3n`, `Ja4`, `Ja4h` - comma-separated. | [TLS Fingerprint Whitelist and Blacklist](k8s/examples/ingress-tls-block-white-and-blacklist.yaml)                                          |
| `guardgress/add-tls-fingerprint-header` | Adds TLS fingerprint/hashes to the request header.                                                             | `Ja3`, `Ja3-Hash`, `Ja3n`, `Ja4`, `Ja4h`.                   | [Add TLS Header](k8s/examples/ingress-add-tls-header.yaml)                                                                                  |
| `guardgress/force-ssl-redirect`         | Forces SSL Redirection. Useful with a TLS certificate.                                                         |                                                             | [Force SSL Redirect](k8s/examples/ingress-force-ssl-redirect.yaml)                                                                          |
| `guardgress/whitelist-ip-source-range`  | Restricts access by allowing only requests from specified IP ranges. Blocks all requests outside these ranges. | ip/cidr - comma-separated values                            | [Whitelist-IP-Source-Range](k8s/examples/ingress-whitelist-ip-source-range.yaml)                                                            |
| `guardgress/limit-ip-whitelist`         | Whitelists IP addresses for rate limiting.                                                                     |                                                             | [Real World Example](k8s/examples/ingress-real-world-example.yaml)                                                                          |
| `guardgress/limit-path-whitelist`       | Whitelists Paths for rate limiting.                                                                            | Exempt specific paths from rate limiting.                   | [Real World Example](k8s/examples/ingress-real-world-example.yaml)                                                                          |
| `guardgress/limit-redis-store-url`      | Defines the URL of the Redis store for rate limiting.                                                          | Default is in-memory store. Essential for HA mode.          | [Rate Limiting with Redis](k8s/examples/ingress-limit-period-with-redis.yaml)                                                               |
| `guardgress/limit-period`               | Sets the rate limit period.                                                                                    | Format: `[number]-[S/M/H/D]` (Second/Minute/Hour/Day).      | [Rate Limiting](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip) |

This Ingress Controller watches Ingress Resources with the `ingressClassName` 
set to "guardgress" or with no `ingressClassName` set at all.

## Installation

### Using Helm
```shell
helm repo add guardgress https://h3adex.github.io/guardgress
helm repo update
helm install guardgress guardgress/guardgress-ingress-controller --namespace guardgress --create-namespace
```

### Using Kubernetes Manifests
```shell
git clone https://github.com/h3adex/guardgress
kubectl apply -f k8s/guardgress-deployment-svc.yaml  # Creates Namespace, SA, CRB, CR, Deployment, Service (LoadBalancer)
kubectl apply -f k8s/guardgress-deployment-hpa.yaml  # Creates HPA
```

After installation, you can define ingress objects using the provided annotations.
Example configurations are available here: [k8s/examples](k8s/examples).

## Development
```sh
make deploy-kind # deploy to local kind cluster
make build-azure # build image and push to azure registry
make help # list available commands
```
This command facilitates container building and controller deployment on a kind cluster.
I've successfully tested the functionality of this ingress-controller on an AKS cluster,
leveraging cert-manager for added support.

Further information on how to set up my local test environment 
can be found in [here](docs/how-to-test.md).

## Monitoring
The Guardgress Ingress Controller is designed with monitoring features in mind.

- Prometheus Metrics Endpoint: Accessible at /metrics, this endpoint consolidates a wide
range of metrics pertinent to HTTP and HTTPS request processing. This provides valuable 
insights into the performance and health of the ingress controller.
- Health Check Endpoint: Available at /healthz, this endpoint is essential for monitoring
the readiness and liveliness of the ingress controller. It plays a crucial role in
maintaining the reliability and stability of the service.

Important Note: Both endpoints are hosted on a dedicated Go server, which listens on 
port **10254**. By default, this server is configured for internal access only, ensuring 
secure operations. To access these metrics externally, you can utilize kubectl port-forward 
to forward the port to your local machine.

For detailed information about each metric we track, 
please refer to the [metrics](docs/existing-metrics.md) documentation.

## Known Limitations
- We ought to transition to Custom Resource Definitions (CRD) to store
  configuration information instead of relying solely on annotations.
  Presently, certain annotations, particularly those containing commas,
  aren't parsed accurately for user-agent configurations.

## License
This project operates under the MIT License. Refer to the [LICENSE](LICENSE) file for details.

## Disclaimer
This project is currently in the development phase and is not recommended for production use. 
It is a Proof of Concept.

## Acknowledgments
- [k8s-simple-ingress-controller](https://github.com/calebdoxsey/kubernetes-simple-ingress-controller) provided a starting point for this project.
- [ja3rp](https://github.com/sleeyax/ja3rp) inspired the creation of this project.
- [fp](https://github.com/gospider007/fp) aided in obtaining client fingerprint information.
- [cidranger](https://github.com/yl2chen/cidranger) provided the IP range matching functionality.
- [limiter](https://github.com/ulule/limiter/) provided the rate limiting functionality.