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

## Deploy JuiceShop 
- TODO

## Deploy the ingress controler with WAF - the most modern and sophisticated insecure web application
- TODO (exposed as service)

## Deploy Deny All Calico policy that block everythig
- kubectl apply -f deny-all.yaml

## Delete Deny All Calico policy that block everythig
- TODO

## Deploy Ingress Controler with mod security and pass traffic to the JuiceShop and phpinfo
- TODO

## Delete the sample apps

- kubectl delete -f phpinfo.yaml
- TODO delete the JuiceShop


