# Azure Kubernetes Cluster - Easy Create

Two scripts that creates Azure Kubernetes Cluster in Resource Group very fast with minimym parameters.

**How To Connect to k8s cluster***
- az login
- az account set --subscription subscrybtion id
- az resource list --resource-group name_of_resourcegroup -o table
- az aks get-credentials --resource-group name_of_resourcegroup --name k8s_cluster_name
- kubectl get nodes
- copy phpinfo.yaml to local disk
- kubectl create -f phpinfo.yaml
- kubectl get pods
- kubectl get service
- browse public IP from several computers and check Hostname:Port - it should be diffrent
- kubectl delete -f phpinfo.yaml


**Deploy Deny All Calico policy***
- kubectl apply -f deny-all.yaml

**k8s-2.json:**

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMariuszFerdyn%2Fk8scluster%2Fmaster%2Fk8s-2.json)

**k8s.json:**

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMariuszFerdyn%2Fk8scluster%2Fmaster%2Fk8s.json)
