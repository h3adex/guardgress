# Guardgress
![Tests](https://github.com/h3adex/guardgress/actions/workflows/test-go-code.yaml/badge.svg)
![Docker](https://github.com/h3adex/guardgress/actions/workflows/publish-to-docker.yaml/badge.svg)

**Note**: This project is currently in the development phase and is not 
recommended for production use. It is a Proof of Concept.

Guardgress showcases a Web Application Firewall (WAF) integration within 
a Kubernetes Ingress Controller. Notably, this project currently lacks 
full support for all functionalities provided by the Ingress API Object.

## Features
- [x] Block Requests based on User-Agent Strings
- [x] Block Requests based on TLS fingerprint (JA3/JA4)
- [x] Add JA4/JA3 fingerprint hash to the request header
- [x] Rate Limit/Throttle Requests coming from a single IP Address
- [ ] Identify connections using proxies. Method described in [this paper](https://dl.acm.org/doi/abs/10.1007/978-3-031-21280-2_18)

Find an example of implementing this controller in 
[Guardgress-Example](https://github.com/h3adex/guardgress-example).

## Images
- [ghcr.io/h3adex/guardgress:latest](https://github.com/h3adex/guardgress/pkgs/container/guardgress)

## Usage
To block requests, utilize specific [annotations](pkg/annotations/annotations.go) on the Ingress API Object:

- `guardgress/user-agent-blacklist`: Blocks requests based on comma-separated User-Agent strings.
- `guardgress/ja3-blacklist`: Blocks requests based on Ja3/Ja3n comma-separated fingerprint hashes.
- `guardgress/ja4-blacklist`: Blocks requests based on Ja4/Ja4n comma-separated fingerprint hashes.
- `guardgress/add-ja3-header`: Adds Ja3/Ja3n fingerprint hash to the request header.
- `guardgress/add-ja4-header`: Adds Ja4/Ja4n fingerprint hash to the request header.
- `guardgress/limit-ip-whitelist`: Whitelists IP addresses for rate limiting.
- `guardgress/limit-period` uses the simplified format "limit-period"", with the given periods:
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

Concrete examples of these annotations can be found in [k8s/examples](k8s/examples).

## Limitations
Please note that Guardgress currently lacks full support for certain functionalities provided by the Ingress API Object.

## Development
```sh
make dev
```
This command facilitates container building and controller deployment on a kind cluster.
I've successfully tested the functionality of this ingress-controller on an AKS cluster,
leveraging cert-manager for added support.

## License
This project operates under the MIT License. Refer to the [LICENSE](LICENSE) file for details.

## Acknowledgments
- [k8s-simple-ingress-controller](https://github.com/calebdoxsey/kubernetes-simple-ingress-controller) provided a starting point for this project.
- [ja3rp](https://github.com/sleeyax/ja3rp) inspired the creation of this project.
- [fp](https://github.com/gospider007/fp) aided in obtaining client fingerprint information.
- [limiter](https://github.com/ulule/limiter/) provided the rate limiting functionality.