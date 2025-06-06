# Kubernetes Ingress Controller with ModSecurity WAF – Playground, Test & Compare with Azure Application Gateway

Kubernetes deployment example featuring an Ingress Controller integrated with ModSecurity as a Web Application Firewall (WAF) for testing and protecting web applications against common threats like SQL injection and cross-site scripting, using the OWASP Core Rule Set—allowing you to compare the results with Azure Application Gateway with WAF.

# ARM template that creates Azure Kubernetes Cluster in Resource Group very fast with minimym parameters.


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
- git clone https://github.com/MariuszFerdyn/k8scluster.git
- cd k8scluster
- python juice_shop_solver.py --url http://...   # Use custom Juice Shop URL

Do it against svc of Ingress and svc of JuiceShop.

# Proxy to External Website via Ingress with ModSecurity
- kubectl apply -f .\ingress-external.yaml

Browse: `http://<INGRESS-IP>/external-service`


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

# Compare with JuiceShop deployed as Container Apps with Application Gateway with WAF

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMariuszFerdyn%2Fk8scluster%2Fmaster%2FJuiceShopContainerAppsWithWAF%2Fjuiceshop-containerapps-w-waf.json)

Do the test against public IP of Application Gateway.

# Tetsing using local kubernetes k3s

## Installation
On Linux Machine e.g. VM.
- curl -sfL https://get.k3s.io | sh -
- cat /etc/rancher/k3s/k3s.yaml

On local Windows Machine:
- notepad $env:USERPROFILE\.kube\config
put it to the content of k3s.yaml replacing 127.0.0.1 with FQDN or server IP. Allow communication on 6443 port and all others that will be used (node port).
- kubectl config set-cluster default --insecure-skip-tls-verify=true
- kubectl get nodes

## Deploy 