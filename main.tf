variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane"
  value       = module.eks.cluster_security_group_id
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = module.eks.cluster_name
}

provider "aws" {
  region = var.region
}

# Filter out local zones, which are not currently supported 
# with managed node groups
data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  cluster_name = "education-eks-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"

  name = "education-vpc"

  cidr = "10.0.0.0/16"
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.8.5"

  cluster_name    = local.cluster_name
  cluster_version = "1.29"

  cluster_endpoint_public_access           = true # set to false and only allow from bastion host
  enable_cluster_creator_admin_permissions = true # set to false when terraform user is different from kube admin

#   cluster_addons = {
# #     aws-ebs-csi-driver = {
# #       service_account_role_arn = module.irsa-ebs-csi.iam_role_arn
# #     }
#     "aws-vpc-cni" = {
#       #version = "1.11.10"  # v1.16.4 for kube 1.31
#     }

#   }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

#   eks_managed_node_group_defaults = {
#     ami_type = "AL2_x86_64"

#   }

#   eks_managed_node_groups = {
#     one = {
#       name = "node-group-1"

#       instance_types = ["t3.micro"]

#       min_size     = 1
#       max_size     = 3
#       desired_size = 2
#     }

    # two = {
    #   name = "node-group-2"

    #   instance_types = ["t3.micro"]

    #   min_size     = 1
    #   max_size     = 2
    #   desired_size = 1
    # }
#   }
}


# https://aws.amazon.com/blogs/containers/amazon-ebs-csi-driver-is-now-generally-available-in-amazon-eks-add-ons/ 
data "aws_iam_policy" "ebs_csi_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

# module "irsa-ebs-csi" {
#   source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
#   version = "5.39.0"

#   create_role                   = true
#   role_name                     = "AmazonEKSTFEBSCSIRole-${module.eks.cluster_name}"
#   provider_url                  = module.eks.oidc_provider
#   role_policy_arns              = [data.aws_iam_policy.ebs_csi_policy.arn]
#   oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
# }

# Create IAM Role for Service Account to use with aws-vpc-cni
resource "aws_iam_role" "vpc_cni_role" {
  name = "eks-vpc-cni-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

# Attach necessary policies to the role
resource "aws_iam_policy" "vpc_cni_policy" {
  name        = "eks-vpc-cni-policy"
  description = "Policy to allow the aws-vpc-cni add-on to interact with EC2, VPC, and related services"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeListeners"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:DescribeInstanceAttribute"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:ec2:*:*:network-interface/*"
      }
    ]
  })
}

# Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "vpc_cni_role_policy_attachment" {
  role       = aws_iam_role.vpc_cni_role.name
  policy_arn = aws_iam_policy.vpc_cni_policy.arn
}

# Create a Kubernetes Service Account (IRSA) for EKS to assume the IAM role
# resource "aws_iam_service_linked_role" "eks_irsa" {
#   aws_service_name = "eks.amazonaws.com"
# }

output "vpc_cni_role_arn" {
  value = aws_iam_role.vpc_cni_role.arn
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name = module.eks.cluster_name
  addon_name   = "vpc-cni"
#   addon_version = "v1.11.9"  # or the appropriate version
#   resolve_conflicts = "OVERWRITE"
  
  service_account_role_arn = aws_iam_role.vpc_cni_role.arn
}

resource "aws_iam_role" "example" {
  name = "eks-node-group-example"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })    
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.example.name
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.example.name
}

resource "aws_iam_role_policy_attachment" "example-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.example.name
}

resource "aws_security_group" "eks_worker_sg" {
  name        = "eks-worker-sg"
  description = "EKS worker node security group"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allows traffic from anywhere (modify as needed)
  }

  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allows outbound traffic to anywhere
  }
}

resource "aws_eks_node_group" "example" {
  cluster_name    = module.eks.cluster_name
  node_group_name = "example"
  node_role_arn   = aws_iam_role.example.arn
  subnet_ids      = module.vpc.private_subnets
  remote_access {
    source_security_group_ids = [aws_security_group.eks_worker_sg.id]
    ec2_ssh_key = "wp"
  }

  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.example-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.example-AmazonEC2ContainerRegistryReadOnly,
  ]
}