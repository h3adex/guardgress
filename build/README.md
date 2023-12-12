## How to Test

After successfully deploying the controller, test its functionality by sending requests 
to the ingress controller.

The [build-dev-env.sh](build-kind.sh) script deploys whoami along with the matching ingress 
controller to the cluster. The script includes annotations necessary for 
the ingress controller's deployment. Running the script for the first time 
prompts the creation of self-signed TLS Certificates.

To test, use the following curl commands:
```sh
# HTTPS
curl -k -H 'host: whoami.local' https://0.0.0.0:444
# HTTP
curl -k -H 'host: whoami.local' http://0.0.0.0:81
```

When testing different ingresses, ensure to use the correct host header. 
The host used to reverse proxy the request is determined in the ingress object.

To test different annotations, use the following kubectl command:
```sh
kubectl edit ingress whoami
```

This will allow you to modify and test various annotations associated 
with the whoami ingress.

### Go Tests
Before running any Go tests, ensure you've added specific entries to your /etc/hosts file:
```txt
127.0.0.1        localhost 127.0.0.1.default.svc.cluster.local 127.0.0.1.test.svc.cluster.local
```
These entries are necessary for server_test.go to function correctly. 
Regrettably, this approach is the current requirement to mimic a 
Kubernetes environment for our tests. If you have alternative solutions, 
I'm open to suggestions.

To execute the Go tests, utilize the following command:
```sh
go test -cover ./pkg/...
```

### Test HPA Functionality
To test the [HPA](../k8s/guardgress-deployment-hpa.yaml) functionality, use the following command:
```sh
echo "GET https://<url>/" | vegeta attack -duration=120s -rate=100/1s
```