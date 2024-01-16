variable "project" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.29"
}

variable "vpc_id" {
  description = "VPC ID where EKS will be deployed"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for EKS nodes"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs for EKS load balancers"
  type        = list(string)
}

variable "kms_key_arn" {
  description = "KMS key ARN for encrypting EKS secrets and EBS volumes"
  type        = string
}

variable "cluster_endpoint_public_access" {
  description = "Enable public access to the EKS cluster API endpoint"
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "List of CIDRs that can access the public EKS API endpoint"
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days for EKS control plane logs"
  type        = number
  default     = 90
}

variable "node_groups" {
  description = "Map of EKS managed node group configurations"
  type = map(object({
    ami_type       = string
    capacity_type  = string
    instance_types = list(string)
    disk_size      = number
    desired_size   = number
    min_size       = number
    max_size       = number
    labels         = map(string)
    taints = list(object({
      key    = string
      value  = string
      effect = string
    }))
  }))
  default = {
    general = {
      ami_type       = "AL2_x86_64"
      capacity_type  = "ON_DEMAND"
      instance_types = ["m5.xlarge"]
      disk_size      = 50
      desired_size   = 2
      min_size       = 1
      max_size       = 10
      labels         = {}
      taints         = []
    }
  }
}

variable "addon_versions" {
  description = "EKS add-on versions"
  type = object({
    vpc_cni        = string
    coredns        = string
    kube_proxy     = string
    ebs_csi_driver = string
  })
  default = {
    vpc_cni        = "v1.16.4-eksbuild.2"
    coredns        = "v1.11.1-eksbuild.4"
    kube_proxy     = "v1.29.1-eksbuild.2"
    ebs_csi_driver = "v1.28.0-eksbuild.1"
  }
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
