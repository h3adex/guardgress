# Guardgress
![Tests](https://github.com/h3adex/guardgress/actions/workflows/test-go-code.yaml/badge.svg)
![Vulnerability Scan](https://github.com/h3adex/guardgress/actions/workflows/vulnerability-scan.yaml/badge.svg)
![Docker](https://github.com/h3adex/guardgress/actions/workflows/publish-to-docker.yaml/badge.svg)

Guardgress showcases a Web Application Firewall (WAF) integration within 
a Kubernetes Ingress Controller. Notably, this project currently lacks 
full support for all functionalities provided by the Ingress API Object.

## Features
- [x] Blacklist/Whitelist User-Agent Strings/Regular Expression
- [x] Block Requests based on TLS fingerprint (Ja3,Ja3-Hash,Ja3n,Ja4,Ja4h)
- [ ] Whitelist Requests based on TLS fingerprint (Ja3,Ja3-Hash,Ja3n,Ja4,Ja4h)
- [x] Add JA4/JA3 fingerprint hash to the request header
- [x] Rate Limit/Throttle Requests coming from a single IP Address
- [x] Use Redis as backend to store rate limiting information
- [x] Force SSL Redirection
- [ ] Identify connections using proxies. Method described in [this paper](https://dl.acm.org/doi/abs/10.1007/978-3-031-21280-2_18)
- [ ] Install as a Helm Chart

## Images
- [ghcr.io/h3adex/guardgress:latest](https://github.com/h3adex/guardgress/pkgs/container/guardgress)

## Usage
To block requests, utilize specific [annotations](pkg/annotations/annotations.go) on the Ingress API Object:

- `guardgress/user-agent-whitelist`: Limits access to specific User-Agents (comma-separated). Whitelist takes precedence over the blacklist. If both are set, anything outside the whitelist is blocked. For an example, check [this configuration](k8s/examples/ingress-ua-block-white-and-blacklist.yaml).
- `guardgress/user-agent-blacklist`: Blocks requests from particular User-Agents (comma-separated).
- `guardgress/tls-fingerprint-blacklist`: Blocks requests based on `Ja3,Ja3-Hash,Ja3n,Ja4,Ja4h` comma-separated fingerprints/hashes.
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

## Development
```sh
make dev
```
This command facilitates container building and controller deployment on a kind cluster.
I've successfully tested the functionality of this ingress-controller on an AKS cluster,
leveraging cert-manager for added support.

Further information on how to set up my local test environment 
can be found in [here](build/README.md).

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