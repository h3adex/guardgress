# Guardgress
![Tests](https://github.com/h3adex/guardgress/actions/workflows/test-go-code.yaml/badge.svg)
![Vulnerability Scan](https://github.com/h3adex/guardgress/actions/workflows/vulnerability-scan.yaml/badge.svg)
![Docker](https://github.com/h3adex/guardgress/actions/workflows/publish-to-docker.yaml/badge.svg)

Guardgress showcases a Web Application Firewall (WAF) integration within 
a Kubernetes Ingress Controller. Notably, this project currently lacks 
full support for all functionalities provided by the Ingress API Object.

## Features
- [x] Block Requests based on User-Agent Strings
- [x] Block Requests based on TLS fingerprint (JA3/JA4)
- [ ] Whitelist Requests based on TLS fingerprint (JA3/JA4)
- [x] Add JA4/JA3 fingerprint hash to the request header
- [x] Rate Limit/Throttle Requests coming from a single IP Address
- [ ] Identify connections using proxies. Method described in [this paper](https://dl.acm.org/doi/abs/10.1007/978-3-031-21280-2_18)
- [ ] Use Redis as backend to store rate limiting information
- [ ] Https redirect/rewrite
- [ ] Install as a Helm Chart

## Images
- [ghcr.io/h3adex/guardgress:latest](https://github.com/h3adex/guardgress/pkgs/container/guardgress)

## Usage
To block requests, utilize specific [annotations](pkg/annotations/annotations.go) on the Ingress API Object:

- `guardgress/user-agent-blacklist`: Blocks requests based on comma-separated User-Agents.
- `guardgress/ja3-blacklist`: Blocks requests based on Ja3/Ja3n comma-separated fingerprints/hashes.
- `guardgress/ja4-blacklist`: Blocks requests based on Ja4/Ja4n comma-separated fingerprints/hashes.
- `guardgress/add-ja3-header`: Adds Ja3/Ja3n fingerprint/hash to the request header.
- `guardgress/add-ja4-header`: Adds Ja4/Ja4n fingerprint/hash to the request header.
- `guardgress/limit-ip-whitelist`: Whitelists IP addresses for rate limiting.
- `guardgress/limit-path-whitelist`: Whitelists Paths for rate limiting. For instance, if you have an ingress object with a Pathtype set as "Prefix" and Path defined as "/shop," you can specify "/shop/products" to be exempted from rate limiting through whitelisting.
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