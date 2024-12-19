# Provider Configuration
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.16"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = var.project_name
    }
  }
}

# VPC Module
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.19"

  name = "${var.project_name}-vpc"
  cidr = "10.0.0.0/16"

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = true
  one_nat_gateway_per_az = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                    = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"           = "1"
  }
}

# EKS Cluster Module
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.5"

  cluster_name    = var.cluster_name
  cluster_version = "1.32"

  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Cluster Encryption Configuration
  create_kms_key = true
  cluster_encryption_config = {
    resources = ["secrets"]
  }

  # EKS Cluster Security Group
  cluster_security_group_additional_rules = {
    ingress = {
      description = "Allow internal communication"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      cidr_blocks = [module.vpc.vpc_cidr_block]
    }
  }

  # Managed Node Groups
  eks_managed_node_groups = {
    core_nodes = {
      name           = "core-node-group"
      instance_types = ["t3.medium"]
      min_size       = 3
      max_size       = 6
      desired_size   = 3

      labels = {
        Environment = "production"
        NodeType    = "core"
      }

      taints = [{
        key    = "core-only"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]
    }

    spot_nodes = {
      name           = "spot-node-group"
      instance_types = ["t3.small", "t3.medium"]
      min_size       = 2
      max_size       = 5
      desired_size   = 2

      use_name_prefix     = true
      capacity_type       = "SPOT"
      force_update_version = true

      labels = {
        Environment = "production"
        NodeType    = "spot"
      }
    }
  }

  # AWS Authentication Configuration
  manage_aws_auth_configmap = true
  aws_auth_roles = [
    {
      rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/admin-role"
      username = "admin-role"
      groups   = ["system:masters"]
    }
  ]
}

# Kubernetes Provider Configuration
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

# Additional Kubernetes Resources
resource "kubernetes_namespace" "monitoring" {
  metadata {
    name = "monitoring"
  }
}

resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace.monitoring.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

# Variables
variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "eks-cluster"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "main-cluster"
}

# Data Sources
data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}

# Outputs
output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  value = module.eks.cluster_security_group_id
}

output "node_security_group_id" {
  value = module.eks.node_security_group_id
}

output "cluster_iam_role_name" {
  value = module.eks.cluster_iam_role_name
}
