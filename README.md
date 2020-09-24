# Azure Kubernetes Cluster - Easy Create

Two scripts that creates Azure Kubernetes Cluster in Resource Group very fast with minimym parameters.

** How To Connect to k8s cluster ***
- az login
- az account set --subscription subscrybtion id
- az resource list --resource-group name_of_resourcegroup -o table
- az aks get-credentials --resource-group name_of_resourcegroup --name k8s_cluster_name
- kubectl get nodes

