# Guardgress
![Tests](https://github.com/h3adex/guardgress/actions/workflows/test-go-code.yaml/badge.svg)
![Vulnerability Scan](https://github.com/h3adex/guardgress/actions/workflows/vulnerability-scan.yaml/badge.svg)
![Docker](https://github.com/h3adex/guardgress/actions/workflows/publish-to-docker.yaml/badge.svg)

Guardgress showcases a Web Application Firewall (WAF) integration within 
a Kubernetes Ingress Controller.

## Features
- [x] User-Agent Filtering: Blacklist/Whitelist with strings or regular expressions.
- [x] TLS Fingerprint Filtering: Whitelist/Blacklist requests based on ``Ja3, Ja3-Hash, Ja3n, Ja4, Ja4h`` fingerprints.
- [x] Request Header Enrichment: Add ``Ja3, Ja3-Hash, Ja3n, Ja4, Ja4h`` tls-fingerprints to the request header.
- [x] IP-Based Rate Limiting: Throttle requests originating from IP Addresses.
- [x] Redis Integration: Utilize Redis as a backend to store and manage rate limiting information efficiently.
- [x] SSL Redirection Enforcement: Ensure SSL connection by enforcing HTTPS through redirection.
- [ ] Helm Chart Installation: Package the application as a Helm Chart for convenient and scalable deployment.

## Images
- [ghcr.io/h3adex/guardgress:latest](https://github.com/h3adex/guardgress/pkgs/container/guardgress)

## Usage
To block requests, utilize specific [annotations](pkg/annotations/annotations.go) on the Ingress API Object:

- `guardgress/user-agent-whitelist`: Limits access to specific User-Agents (comma-separated). Whitelist takes precedence over the blacklist. If both are set, anything outside the whitelist is blocked. For an example, check [this configuration](k8s/examples/ingress-ua-block-white-and-blacklist.yaml).
- `guardgress/user-agent-blacklist`: Blocks requests from particular User-Agents (comma-separated).
- `guardgress/tls-fingerprint-whitelist`: Limits access to specific TLS Fingerprints (`Ja3`, `Ja3-Hash`, `Ja3n`, `Ja4`, `Ja4h` - comma-separated). Whitelist takes precedence over the blacklist. If both are set, anything outside the whitelist is blocked. Find an example configuration [here](k8s/examples/ingress-tls-block-white-and-blacklist.yaml).
- `guardgress/tls-fingerprint-blacklist`: Restricts requests from particular TLS Fingerprints (`Ja3`, `Ja3-Hash`, `Ja3n`, `Ja4`, `Ja4h` - comma-separated).
- `guardgress/add-tls-fingerprint-header`: Adds `Ja3,Ja3-Hash,Ja3n,Ja4,Ja4h` fingerprints/hashes to the request header.
- `guardgress/force-ssl-redirect`: Forces SSL Redirection. This annotation is only useful if you have a TLS certificate configured for your ingress object.
- `guardgress/limit-ip-whitelist`: Whitelists IP addresses for rate limiting.
- `guardgress/limit-path-whitelist`: Whitelists Paths for rate limiting. For instance, if you have an ingress object with a Pathtype set as "Prefix" and Path defined as "/shop," you can specify "/shop/products" to be exempted from rate limiting through whitelisting.
- `guardgress/limit-redis-store-url`: This parameter defines the URL of the Redis store. If left unspecified, the controller resorts to an in-memory store. Redis becomes essential particularly when operating in High Availability (HA) Mode with multiple pods.
- `guardgress/limit-period` uses the simplified format "limit-period", with the given periods:
```text
"S": second 
"M": minute
"H": hour
"D": day

Examples:
    
5 reqs/second: "5-S"
10 reqs/minute: "10-M"
1000 reqs/hour: "1000-H"
2000 reqs/day: "2000-D"
```
If you want to use the limit-period annotation, make sure to set externalTrafficPolicy to Local in the service object of the ingress controller. 
Otherwise, the rate limiting will not work as intended. More Information can be found here: https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip

Concrete examples of these annotations can be found in [k8s/examples](k8s/examples).

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