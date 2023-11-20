# Guardgress

Note: This project is currently in the development phase and 
is not recommended for production use. It is a Proof of Concept.

Guardgress is a project designed to demonstrate the implementation of a Web Application Firewall (WAF) 
within a Kubernetes Ingress Controller. It's important to note that this project currently 
does not fully support all functionalities provided by the Ingress API Object.

See [Guardgress-Example](https://github.com/h3adex/guardgress-example) 
for an example on how to use this controller.

## Development
```sh
make dev
```

Builds the container and deploys the controller to a kind cluster.

## Usage
More comprehensive examples on how to utilize this project will be provided in subsequent updates.

## License
This project falls under the MIT License.
The included (and then modified) `net/http`, `internal/profile` and `crypto` packages fall under the [go source code license](https://github.com/golang/go/blob/master/LICENSE).

## Thanks
- [k8s-simple-ingress-controller](https://github.com/calebdoxsey/kubernetes-simple-ingress-controller) gave me a good starting point for this project.
- [ja3rp](https://github.com/sleeyax/ja3rp) is a project which inspired me to create this project.
