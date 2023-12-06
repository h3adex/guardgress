## How to Test

After successfully deploying the controller, test its functionality by sending requests 
to the ingress controller.

The [build-dev-env.sh](build-dev-env.sh) script deploys whoami along with the matching ingress 
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