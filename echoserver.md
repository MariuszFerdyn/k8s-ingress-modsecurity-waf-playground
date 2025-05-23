# Echo Server Deployment

This manifest deploys a simple echo server using the image `gcr.io/kubernetes-e2e-test-images/echoserver:2.1` with a single replica and exposes it via a LoadBalancer service on port 8081.

## How To Deploy Echo Server

- kubectl create -f echoserver.yaml
- kubectl get pods
- kubectl get service
- Access the echo server using the public IP and port 8081

## Delete Echo Server

- kubectl delete -f echoserver.yaml
