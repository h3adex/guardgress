# Guardgress


**Note**: This project is currently in the development phase and is not 
recommended for production use. It is a Proof of Concept.

Guardgress showcases a Web Application Firewall (WAF) integration within 
a Kubernetes Ingress Controller. Notably, this project currently lacks 
full support for all functionalities provided by the Ingress API Object.

## Features
- [x] Block Requests based on User-Agent Strings
- [x] Block Requests based on Ja3/Ja4 fingerprint
- [x] Add Ja4/Ja3 fingerprint hash to the request header

Find an example of implementing this controller in 
[Guardgress-Example](https://github.com/h3adex/guardgress-example).

## Images
- [ghcr.io/h3adex/guardgress:latest](https://github.com/h3adex/guardgress/pkgs/container/guardgress)

## Usage
To block requests, utilize specific annotations on the Ingress API Object:

- `guardgress/user-agent-blacklist`: Blocks requests based on comma-separated User-Agent strings.
- `guardgress/ja3-blacklist`: Blocks requests based on Ja3/Ja3n comma-separated fingerprint hashes.
- `guardgress/ja4-blacklist`: Blocks requests based on Ja4/Ja4n comma-separated fingerprint hashes.
- `guardgress/add-ja3-header`: Adds Ja3/Ja3n fingerprint hash to the request header.
- `guardgress/add-ja4-header`: Adds Ja4/Ja4n fingerprint hash to the request header.

Concrete examples of these annotations can be found in [k8s/examples](k8s/examples).

## Limitations
Please note that Guardgress currently lacks full support for certain functionalities provided by the Ingress API Object.

## Development
```sh
make dev
```
This command builds the container and deploys the controller to a kind cluster.

## License
This project operates under the MIT License. Refer to the [LICENSE](LICENSE) file for details.

## Acknowledgments
- [k8s-simple-ingress-controller](https://github.com/calebdoxsey/kubernetes-simple-ingress-controller) provided a starting point for this project.
- [ja3rp](https://github.com/sleeyax/ja3rp) inspired the creation of this project.
- [fp](https://github.com/gospider007/fp) aided in obtaining client fingerprint information.