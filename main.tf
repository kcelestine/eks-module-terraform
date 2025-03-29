data "aws_availability_zones" "available" {}

resource "aws_vpc" "main" {
 cidr_block = "10.0.0.0/16"

 tags = {
   Name = "main-vpc-eks"
 }
}

resource "aws_subnet" "public_subnet" {
 count                   = 2
 vpc_id                  = aws_vpc.main.id
 cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
 availability_zone       = data.aws_availability_zones.available.names[count.index]
 map_public_ip_on_launch = true

 tags = {
   Name = "public-subnet-${count.index}"
 }
}

resource "aws_internet_gateway" "main" {
 vpc_id = aws_vpc.main.id

 tags = {
   Name = "main-igw"
 }
}

resource "aws_route_table" "public" {
 vpc_id = aws_vpc.main.id

 route {
   cidr_block = "0.0.0.0/0"
   gateway_id = aws_internet_gateway.main.id
 }

 tags = {
   Name = "main-route-table"
 }
}

resource "aws_route_table_association" "a" {
 count          = 2
 subnet_id      = aws_subnet.public_subnet.*.id[count.index]
 route_table_id = aws_route_table.public.id
}

module "eks" {
 source  = "terraform-aws-modules/eks/aws"
 version = "~> 20.31"

 cluster_name    = "example"
 cluster_version = "1.31"

 # Optional
 cluster_endpoint_public_access = true

 # Optional: Adds the current caller identity as an administrator via cluster access entry
 enable_cluster_creator_admin_permissions = true

 eks_managed_node_groups = {
   example = {
     instance_types = ["t3.medium"]
     min_size       = 1
     max_size       = 3
     desired_size   = 2
   }
 }
cluster_addons = {
    coredns = {
      preserve    = true
      most_recent = true

      timeouts = {
        create = "25m"
        delete = "10m"
      }
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
  }
 vpc_id     = aws_vpc.main.id
 subnet_ids = aws_subnet.public_subnet.*.id

 tags = {
   Environment = "dev"
   Terraform   = "true"
 }
}

# # Create IAM Role for Service Account to use with aws-vpc-cni
# resource "aws_iam_role" "vpc_cni_role" {
#   name = "eks-vpc-cni-role"

#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRole"
#         Effect = "Allow"
#         Principal = {
#           Service = "eks.amazonaws.com"
#         }
#       }
#     ]
#   })
# }

# # Attach necessary policies to the role
# resource "aws_iam_policy" "vpc_cni_policy" {
#   name        = "eks-vpc-cni-policy"
#   description = "Policy to allow the aws-vpc-cni add-on to interact with EC2, VPC, and related services"
#   policy      = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = [
#           "ec2:DescribeSecurityGroups",
#           "ec2:DescribeInstances",
#           "ec2:DescribeSubnets",
#           "ec2:DescribeRouteTables",
#           "ec2:CreateNetworkInterface",
#           "ec2:DescribeNetworkInterfaces",
#           "ec2:DeleteNetworkInterface",
#           "ec2:AssignPrivateIpAddresses",
#           "ec2:UnassignPrivateIpAddresses"
#         ]
#         Effect   = "Allow"
#         Resource = "*"
#       },
#       {
#         Action = [
#           "elasticloadbalancing:DescribeLoadBalancers",
#           "elasticloadbalancing:DescribeTargetGroups",
#           "elasticloadbalancing:DescribeListeners"
#         ]
#         Effect   = "Allow"
#         Resource = "*"
#       },
#       {
#         Action = [
#           "ec2:ModifyInstanceAttribute",
#           "ec2:DescribeInstanceAttribute"
#         ]
#         Effect   = "Allow"
#         Resource = "*"
#       },
#       {
#         Action = [
#           "ec2:CreateTags",
#           "ec2:DeleteTags"
#         ]
#         Effect   = "Allow"
#         Resource = "arn:aws:ec2:*:*:network-interface/*"
#       }
#     ]
#   })
# }

# # Attach the policy to the IAM role
# resource "aws_iam_role_policy_attachment" "vpc_cni_role_policy_attachment" {
#   role       = aws_iam_role.vpc_cni_role.name
#   policy_arn = aws_iam_policy.vpc_cni_policy.arn
# }

# # Create a Kubernetes Service Account (IRSA) for EKS to assume the IAM role
# # resource "aws_iam_service_linked_role" "eks_irsa" {
# #   aws_service_name = "eks.amazonaws.com"
# # }

# output "vpc_cni_role_arn" {
#   value = aws_iam_role.vpc_cni_role.arn
# }

# resource "aws_eks_addon" "vpc_cni" {
#   cluster_name = module.eks.cluster_name
#   addon_name   = "vpc-cni"
# #   addon_version = "v1.11.9"  # or the appropriate version
# #   resolve_conflicts = "OVERWRITE"
  
#   service_account_role_arn = aws_iam_role.vpc_cni_role.arn
# }
