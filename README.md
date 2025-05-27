# Azure Kubernetes Cluster - Easy Create

ARM template that creates Azure Kubernetes Cluster in Resource Group very fast with minimym parameters.


[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMariuszFerdyn%2Fk8scluster%2Fmaster%2Fk8s-2.json)



## How To Connect to k8s cluster and deploy sample application (phpinfo)
- git clone https://github.com/MariuszFerdyn/k8scluster.git
- az login
- az account set --subscription subscrybtion id
- az resource list --resource-group name_of_resourcegroup -o table
- az aks get-credentials --resource-group name_of_resourcegroup --name k8s_cluster_name
- kubectl get nodes
- kubectl create -f phpinfo.yaml
- kubectl get pods
- kubectl get service
- browse public IP from several computers and check External-IP:8080 - it should be diffrent

## Deploy Echo Server
- kubectl create -f echoserver.yaml
- kubectl get pods
- kubectl get service
- Access the echo server using the External-IP and port 8081


## Deploy JuiceShop 
- kubectl create -f juiceshop.yaml
- kubectl get service
- browse public IP from several computers and check External-IP:3000


## Deploy the ingress controller with ModSecurity (WAF)
- helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
- helm install ingress ingress-nginx/ingress-nginx -f .\ingress-values.yaml


## Expose applicationx via ingress
- kubectl apply -f ingress.yaml

### Access applications via Ingress
- kubectl get ingress
- JuiceShop:   `http://<INGRESS-IP>/`
- phpinfo:     `http://<INGRESS-IP>/phpinfo`
- Echo Server: `http://<INGRESS-IP>/echoserver`

Replace `<INGRESS-IP>` with the actual external IP address of your ingress controller (check with `kubectl get ingress`).

# Tests
## Deploy contaner with python and connect to it interactyvly
- kubectl run -it --rm python-interactive --image=python:3.11 --restart=Never -- bash


## Deploy Deny All Calico policy that block everythig
- kubectl apply -f deny-all.yaml

## Delete Deny All Calico policy that block everythig
- TODO



# Delete

- kubectl delete -f phpinfo.yaml
- kubectl delete -f juiceshop.yaml
- kubectl delete -f echoserver.yaml
- kubectl delete -f ingress.yaml
- helm uninstall ingress