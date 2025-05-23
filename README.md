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
- browse public IP from several computers and check Hostname:Port - it should be diffrent

## Deploy Echo Server
- kubectl create -f echoserver.yaml
- kubectl get pods
- kubectl get service
- Access the echo server using the public IP and port 8081



## Deploy JuiceShop 
- kubectl create -f juiceshop.yaml
- kubectl get service
- browse public IP from several computers and check Hostname:Port 


## Deploy the ingress controller with ModSecurity (WAF)
- Ensure you have an NGINX Ingress controller deployed with ModSecurity enabled (see official docs for setup).
- Edit and apply the provided ingress manifest:
  - kubectl apply -f meow-ingress.yaml
- This will create an ingress with ModSecurity enabled and a sample rule blocking User-Agent 'bad-scanner'.
- Make sure the backend service `meow-svc` exists and is listening on port 80.

## Deploy Deny All Calico policy that block everythig
- kubectl apply -f deny-all.yaml

## Delete Deny All Calico policy that block everythig
- TODO



## Deploy Ingress Controller with ModSecurity for JuiceShop and phpinfo
- You can adapt the `meow-ingress.yaml` example for other services (e.g., JuiceShop, phpinfo) by changing the service name and path.

## Delete the sample apps

- kubectl delete -f phpinfo.yaml
- kubectl delete -f juiceshop.yaml
- kubectl delete -f echoserver.yaml
