provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  name    = "EMRSparkAIVPC"
  version = "3.14.0"

  azs             = data.aws_availability_zones.available.names
  cidr            = var.vpc_cidr_block
  private_subnets = slice(var.private_subnet_cidr_blocks, 0, 2)
  public_subnets  = slice(var.public_subnet_cidr_blocks, 0, 2)

  instance_tenancy        = "default"
  enable_dns_support      = true
  enable_dns_hostnames    = true
  map_public_ip_on_launch = true
  enable_nat_gateway      = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = {
    "Name"                                     = "EMR-SparkAI-VPC"
    "for-use-with-amazon-emr-managed-policies" = "true"
  }
}

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "zone-type"
    values = ["availability-zone"]
  }
}

resource "aws_vpc_endpoint" "S3Endpoint" {
  vpc_id       = module.vpc.vpc_id
  service_name = "com.amazonaws.${var.aws_region}.s3"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Action    = "*",
        Principal = "*",
        Resource  = "*",
      },
    ],
  })

  route_table_ids = flatten([module.vpc.private_route_table_ids, module.vpc.public_route_table_ids])
}

resource "aws_security_group" "EMRSparkAISecGroup" {
  name        = "EMRSparkAI-Default-SG"
  description = "Default security group that allows inbound and outbound traffic from all instances in the VPC."
  vpc_id      = module.vpc.vpc_id

  revoke_rules_on_delete = true

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      var.vpc_cidr_block,
    ]
  }

  tags = {
    Name = "EMRSparkAI-Default-SG"
  }
}

resource "aws_security_group_rule" "VPCDefaultSecurityGroupIngress" {
  from_port         = 0
  to_port           = 0
  security_group_id = module.vpc.default_security_group_id
  type              = "ingress"
  protocol          = "-1"
  cidr_blocks       = [var.vpc_cidr_block]
}

resource "aws_s3_bucket" "EMRSparkAIBucket" {
  bucket = join("-", ["emr-sparkai", data.aws_caller_identity.current.account_id])

  force_destroy = true # Note: this should be turned off to not delete S3 bucket on prod
}

resource "aws_iam_role" "SCLaunchRole" {
  name = "EMRSparkAI-SCLaunchRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = ["elasticmapreduce.amazonaws.com", "servicecatalog.amazonaws.com"]
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  inline_policy {
    name   = var.sc_launch_role_inline_policy_name
    policy = data.aws_iam_policy_document.sc_launch_role_inline_policy.json
  }
}

data "aws_iam_policy_document" "sc_launch_role_inline_policy" {
  statement {
    effect = "Allow"
    actions = [
      "catalog-user:*",
      "s3:GetObject",
      "elasticmapreduce:*",
    ]
    resources = ["*"]
  }

  statement {
    effect  = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      aws_iam_role.EMREC2RestrictedRole.arn,
      aws_iam_role.EMRClusterServiceRole.arn,
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/EMR_AutoScaling_DefaultRole",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/EMR_DefaultRole",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/EMR_EC2_DefaultRole",
    ]
  }
}

resource "aws_iam_role" "EMREC2RestrictedRole" {
  name = "EMREC2RestrictedRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  inline_policy {
    name   = var.emr_ec2_restricted_role_inline_policy_name
    policy = data.aws_iam_policy_document.emr_ec2_restricted_role_inline_policy.json
  }
}

data "aws_iam_policy_document" "emr_ec2_restricted_role_inline_policy" {
  statement {
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.EMRSparkAIBucket.arn}/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.EMRSparkAIBucket.arn}/*"]
  }

  statement {
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    resources = [
      "arn:aws:s3:::${var.aws_region}.elasticmapreduce",
      "arn:aws:s3:::aws-data-analytics-blog",
      "arn:aws:s3:::aws-data-analytics-workshops",
      "arn:aws:s3:::aws-blogs-artifacts-public",
      "arn:aws:s3:::serverless-analytics",
      aws_s3_bucket.EMRSparkAIBucket.arn,
    ]
  }

  statement {
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = [
      "arn:aws:s3:::${var.aws_region}.elasticmapreduce/*",
      "arn:aws:s3:::aws-data-analytics-workshops/emr-dev-exp-workshop/*",
      "arn:aws:s3:::aws-data-analytics-workshops/emr/*",
      "arn:aws:s3:::aws-data-analytics-workshops/blogs/emr-genai/*",
      "arn:aws:s3:::aws-blogs-artifacts-public/artifacts/BDB-3655/*",
      "arn:aws:s3:::serverless-analytics/*",
      "${aws_s3_bucket.EMRSparkAIBucket.arn}/*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "cloudwatch:*",
      "dynamodb:*",
      "ec2:Describe*",
      "elasticmapreduce:Describe*",
      "elasticmapreduce:ListBootstrapActions",
      "elasticmapreduce:ListClusters",
      "elasticmapreduce:ListInstanceGroups",
      "elasticmapreduce:ListInstances",
      "elasticmapreduce:ListSteps",
      "kinesis:*",
      "rds:Describe*",
      "sdb:*",
      "sns:*",
      "sqs:*",
      "glue:*",
      "bedrock:InvokeModel",
      "bedrock:ListFoundationModels",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_instance_profile" "EMREC2RestrictedRoleInstanceProfile" {
  name = "EMRSparkAI-EMR_EC2_Restricted_Role"
  path = "/"
  role = aws_iam_role.EMREC2RestrictedRole.name
}

resource "aws_iam_role" "EMRClusterServiceRole" {
  name = "EMRSparkAI-EMRClusterServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "elasticmapreduce.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"]
  path                = "/"
}

resource "aws_iam_role" "EMRStudioServiceRole" {
  name = "EMRSparkAI-StudioServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "elasticmapreduce.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  inline_policy {
    name   = var.emr_studio_service_role_inline_policy_name
    policy = data.aws_iam_policy_document.emr_studio_service_role_inline_policy.json
  }
}

data "aws_iam_policy_document" "emr_studio_service_role_inline_policy" {
  statement {
    sid    = "AllowEMRReadOnlyActions"
    effect = "Allow"
    actions = [
      "elasticmapreduce:ListInstances",
      "elasticmapreduce:DescribeCluster",
      "elasticmapreduce:ListSteps",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowEC2ENIActionsWithEMRTags"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterfacePermission",
      "ec2:DeleteNetworkInterface",
    ]
    resources = ["arn:aws:ec2:*:*:network-interface/*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:ResourceTag/for-use-with-amazon-emr-managed-policies"
      values   = ["true"]
    }
  }

  statement {
    sid     = "AllowEC2ENIAttributeAction"
    effect  = "Allow"
    actions = ["ec2:ModifyNetworkInterfaceAttribute"]
    resources = [
      "arn:aws:ec2:*:*:instance/*",
      "arn:aws:ec2:*:*:network-interface/*",
      "arn:aws:ec2:*:*:security-group/*",
    ]
  }

  statement {
    sid       = "AllowDefaultEC2SecurityGroupsCreationWithEMRTags"
    effect    = "Allow"
    actions   = ["ec2:CreateSecurityGroup"]
    resources = ["arn:aws:ec2:*:*:security-group/*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:RequestTag/for-use-with-amazon-emr-managed-policies"
      values   = ["true"]
    }
  }

  statement {
    sid       = "AllowDefaultEC2SecurityGroupsCreationInVPCWithEMRTags"
    effect    = "Allow"
    actions   = ["ec2:CreateSecurityGroup"]
    resources = ["arn:aws:ec2:*:*:vpc/*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:ResourceTag/for-use-with-amazon-emr-managed-policies"
      values   = ["true"]
    }
  }

  statement {
    sid       = "AllowAddingEMRTagsDuringDefaultSecurityGroupCreation"
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:*:*:security-group/*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:RequestTag/for-use-with-amazon-emr-managed-policies"
      values   = ["true"]
    }
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSecurityGroup"]
    }
  }

  statement {
    sid       = "AllowEC2ENICreationWithEMRTags"
    effect    = "Allow"
    actions   = ["ec2:CreateNetworkInterface"]
    resources = ["arn:aws:ec2:*:*:network-interface/*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:RequestTag/for-use-with-amazon-emr-managed-policies"
      values   = ["true"]
    }
  }

  statement {
    sid       = "AllowEC2ENICreationInSubnetAndSecurityGroupWithEMRTags"
    effect    = "Allow"
    actions   = ["ec2:CreateNetworkInterface"]
    resources = ["arn:aws:ec2:*:*:subnet/*", "arn:aws:ec2:*:*:security-group/*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:ResourceTag/for-use-with-amazon-emr-managed-policies"
      values   = ["true"]
    }
  }

  statement {
    sid       = "AllowAddingTagsDuringEC2ENICreation"
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:*:*:network-interface/*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateNetworkInterface"]
    }
  }

  statement {
    sid    = "AllowEC2ReadOnlyActions"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeTags",
      "ec2:DescribeInstances",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "AllowSecretsManagerReadOnlyActionsWithEMRTags"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:*:*:secret:*"]
    condition {

      test     = "ForAnyValue:StringEquals"
      variable = "aws:ResourceTag/for-use-with-amazon-emr-managed-policies"
      values   = ["true"]

    }
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetEncryptionConfiguration", "s3:ListBucket", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::*"]
  }
}

resource "aws_iam_role" "EMRStudioUserRole" {
  name = "EMRSparkAI-StudioUserRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "elasticmapreduce.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AWSServiceCatalogEndUserFullAccess",
    aws_iam_policy.StudioAdvanceUserSessionPolicy.arn,
    aws_iam_policy.StudioIntermediateUserSessionPolicy.arn
  ]
}

resource "aws_iam_policy" "StudioAdvanceUserSessionPolicy" {
  name = "StudioAdvanceUserSessionPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "elasticmapreduce:CreateEditor",
          "elasticmapreduce:DescribeEditor",
          "elasticmapreduce:ListEditors",
          "elasticmapreduce:StartEditor",
          "elasticmapreduce:StopEditor",
          "elasticmapreduce:DeleteEditor",
          "elasticmapreduce:OpenEditorInConsole",
          "elasticmapreduce:AttachEditor",
          "elasticmapreduce:DetachEditor",
          "elasticmapreduce:CreateRepository",
          "elasticmapreduce:DescribeRepository",
          "elasticmapreduce:DeleteRepository",
          "elasticmapreduce:ListRepositories",
          "elasticmapreduce:LinkRepository",
          "elasticmapreduce:UnlinkRepository",
          "elasticmapreduce:DescribeCluster",
          "elasticmapreduce:ListInstanceGroups",
          "elasticmapreduce:ListBootstrapActions",
          "elasticmapreduce:ListClusters",
          "elasticmapreduce:ListSteps",
          "elasticmapreduce:CreatePersistentAppUI",
          "elasticmapreduce:DescribePersistentAppUI",
          "elasticmapreduce:GetPersistentAppUIPresignedURL",
        ]
        Effect   = "Allow"
        Resource = "*"
        Sid      = "AllowEMRBasicActions"
      },
      {
        Sid = "AllowEMRContainersBasicActions"
        Action = [
          "emr-containers:DescribeVirtualCluster",
          "emr-containers:ListVirtualClusters",
          "emr-containers:DescribeManagedEndpoint",
          "emr-containers:ListManagedEndpoints",
          "emr-containers:CreateAccessTokenForManagedEndpoint",
          "emr-containers:DescribeJobRun",
          "emr-containers:ListJobRuns",
        ]
        Resource = "*"
        Effect   = "Allow"
      },
      {
        Sid = "AllowSecretManagerListSecrets"
        Action = [
          "secretsmanager:ListSecrets",
          "secretsmanager:CreateSecret",
          "secretsmanager:TagResource",
        ]
        Resource = "*"
        Effect   = "Allow"
      },
      {
        Sid      = "AllowSecretCreationWithEMRTagsAndEMRStudioPrefix"
        Effect   = "Allow"
        Action   = ["secretsmanager:CreateSecret"]
        Resource = "arn:aws:secretsmanager:*:*:secret:emr-studio-*"
        Condition = {
          StringEquals = {
            "aws:RequestTag/for-use-with-amazon-emr-managed-policies" = "true"
          }
        }
      },
      {
        Sid      = "AllowAddingTagsOnSecretsWithEMRStudioPrefix"
        Effect   = "Allow"
        Action   = ["secretsmanager:TagResource"]
        Resource = "arn:aws:secretsmanager:*:*:secret:emr-studio-*"
      },
      {
        Sid    = "AllowClusterTemplateRelatedIntermediateActions"
        Effect = "Allow"
        Action = [
          "servicecatalog:DescribeProduct",
          "servicecatalog:DescribeProductView",
          "servicecatalog:DescribeProvisioningParameters",
          "servicecatalog:ProvisionProduct",
          "servicecatalog:SearchProducts",
          "servicecatalog:UpdateProvisionedProduct",
          "servicecatalog:ListProvisioningArtifacts",
          "servicecatalog:ListLaunchPaths",
          "servicecatalog:DescribeRecord",
        ]
        Resource = "*"
      },
      {
        Sid      = "AllowEMRCreateClusterAdvancedActions"
        Effect   = "Allow"
        Action   = ["elasticmapreduce:RunJobFlow"]
        Resource = "*"
      },
      {
        Sid    = "PassRolePermission"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          "${aws_iam_role.EMRClusterServiceRole.arn}",
          "${aws_iam_role.EMREC2RestrictedRole.arn}",
          "${aws_iam_role.EMRStudioServiceRole.arn}",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/EMR_DefaultRole",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}"
        ]
      },
      {
        Action   = ["s3:*"]
        Resource = ["${aws_s3_bucket.EMRSparkAIBucket.arn}"]
        Effect   = "Allow"
        Sid      = "S3ListPermission"
      },
      {
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.EMRSparkAIBucket.arn}/*"]
        Effect   = "Allow"
      },
      {
        Action   = ["s3:ListAllMyBuckets"]
        Resource = ["*"]
        Effect   = "Allow"
      }
    ]
  })
}

resource "aws_iam_policy" "StudioIntermediateUserSessionPolicy" {
  name = "EMRSparkAI-StudioIntermediateUserSessionPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "elasticmapreduce:CreateEditor",
          "elasticmapreduce:DescribeEditor",
          "elasticmapreduce:ListEditors",
          "elasticmapreduce:StartEditor",
          "elasticmapreduce:StopEditor",
          "elasticmapreduce:DeleteEditor",
          "elasticmapreduce:OpenEditorInConsole",
          "elasticmapreduce:AttachEditor",
          "elasticmapreduce:DetachEditor",
          "elasticmapreduce:CreateRepository",
          "elasticmapreduce:DescribeRepository",
          "elasticmapreduce:DeleteRepository",
          "elasticmapreduce:ListRepositories",
          "elasticmapreduce:LinkRepository",
          "elasticmapreduce:UnlinkRepository",
          "elasticmapreduce:DescribeCluster",
          "elasticmapreduce:ListInstanceGroups",
          "elasticmapreduce:ListBootstrapActions",
          "elasticmapreduce:ListClusters",
          "elasticmapreduce:ListSteps",
          "elasticmapreduce:CreatePersistentAppUI",
          "elasticmapreduce:DescribePersistentAppUI",
          "elasticmapreduce:GetPersistentAppUIPresignedURL"
        ]
        Resource = ["*"]
        Effect   = "Allow"
        Sid      = "AllowEMRBasicActions"
      },
      {
        Action = [
          "emr-containers:DescribeVirtualCluster",
          "emr-containers:ListVirtualClusters",
          "emr-containers:DescribeManagedEndpoint",
          "emr-containers:ListManagedEndpoints",
          "emr-containers:CreateAccessTokenForManagedEndpoint",
          "emr-containers:DescribeJobRun",
          "emr-containers:ListJobRuns"
        ]
        Resource = ["*"]
        Effect   = "Allow"
        Sid      = "AllowEMRContainersBasicActions"
      },
      {
        Action = [
          "secretsmanager:ListSecrets",
          "secretsmanager:CreateSecret",
          "secretsmanager:TagResource"
        ]
        Resource = ["*"]
        Effect   = "Allow"
        Sid      = "AllowSecretManagerListSecrets"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:CreateSecret"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:emr-studio-*"]
        Condition = {
          StringEquals = {
            "aws:RequestTag/for-use-with-amazon-emr-managed-policies" = "true"
          }
        }
        Sid = "AllowSecretCreationWithEMRTagsAndEMRStudioPrefix"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:TagResource"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:emr-studio-*"]
        Sid      = "AllowAddingTagsOnSecretsWithEMRStudioPrefix"
      },
      {
        Action = [
          "servicecatalog:DescribeProduct",
          "servicecatalog:DescribeProductView",
          "servicecatalog:DescribeProvisioningParameters",
          "servicecatalog:ProvisionProduct",
          "servicecatalog:SearchProducts",
          "servicecatalog:UpdateProvisionedProduct",
          "servicecatalog:ListProvisioningArtifacts",
          "servicecatalog:ListLaunchPaths",
          "servicecatalog:DescribeRecord"
        ]
        Resource = ["*"]
        Effect   = "Allow"
        Sid      = "AllowClusterTemplateRelatedIntermediateActions"
      },
      {
        Action = ["iam:PassRole"]
        Resource = [
          "${aws_iam_role.EMRClusterServiceRole.arn}"
        ]
        Effect = "Allow"
        Sid    = "PassRolePermission"
      },
      {
        Action   = ["s3:*"]
        Resource = ["${aws_s3_bucket.EMRSparkAIBucket.arn}/*"]
        Effect   = "Allow"
        Sid      = "S3ListPermission"
      },
      {
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.EMRSparkAIBucket.arn}/*"]
        Effect   = "Allow"
      },
      {
        Action   = ["s3:ListAllMyBuckets"]
        Resource = ["*"]
        Effect   = "Allow"
      }
    ]
  })
}

resource "aws_iam_policy" "AmazonEMROnEKSPolicy" {
  name = "EMRSparkAI-AmazonEMROnEKSPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "elasticmapreduce:CreateEditor",
          "elasticmapreduce:DescribeEditor",
          "elasticmapreduce:ListEditors",
          "elasticmapreduce:StartEditor",
          "elasticmapreduce:StopEditor",
          "elasticmapreduce:DeleteEditor",
          "elasticmapreduce:OpenEditorInConsole",
          "elasticmapreduce:AttachEditor",
          "elasticmapreduce:DetachEditor",
          "elasticmapreduce:CreateRepository",
          "elasticmapreduce:DescribeRepository",
          "elasticmapreduce:DeleteRepository",
          "elasticmapreduce:ListRepositories",
          "elasticmapreduce:LinkRepository",
          "elasticmapreduce:UnlinkRepository",
          "elasticmapreduce:DescribeCluster",
          "elasticmapreduce:ListInstanceGroups",
          "elasticmapreduce:ListBootstrapActions",
          "elasticmapreduce:ListClusters",
          "elasticmapreduce:ListSteps",
          "elasticmapreduce:CreatePersistentAppUI",
          "elasticmapreduce:DescribePersistentAppUI",
          "elasticmapreduce:GetPersistentAppUIPresignedURL",
          "secretsmanager:CreateSecret",
          "secretsmanager:ListSecrets",
          "emr-containers:DescribeVirtualCluster",
          "emr-containers:ListVirtualClusters",
          "emr-containers:DescribeManagedEndpoint",
          "emr-containers:ListManagedEndpoints",
          "emr-containers:CreateAccessTokenForManagedEndpoint",
          "emr-containers:DescribeJobRun",
          "emr-containers:ListJobRuns"
        ]
        Resource = ["*"]
        Effect   = "Allow"
        Sid      = "AllowBasicActions"
      },
      {
        Action = [
          "servicecatalog:DescribeProduct",
          "servicecatalog:DescribeProductView",
          "servicecatalog:DescribeProvisioningParameters",
          "servicecatalog:ProvisionProduct",
          "servicecatalog:SearchProducts",
          "servicecatalog:UpdateProvisionedProduct",
          "servicecatalog:ListProvisioningArtifacts",
          "servicecatalog:DescribeRecord"
        ]
        Resource = ["*"]
        Effect   = "Allow"
        Sid      = "AllowIntermediateActions"
      },
      {
        Action   = ["elasticmapreduce:RunJobFlow"]
        Resource = ["*"]
        Effect   = "Allow"
        Sid      = "AllowAdvancedActions"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:CreateServiceLinkedRole"]
        Resource = ["*"]
        Condition = {
          StringLike = {
            "iam:AWSServiceName" = "emr-containers.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "emr-containers:CreateVirtualCluster",
          "emr-containers:ListVirtualClusters",
          "emr-containers:DescribeVirtualCluster",
          "emr-containers:DeleteVirtualCluster"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "emr-containers:StartJobRun",
          "emr-containers:ListJobRuns",
          "emr-containers:DescribeJobRun",
          "emr-containers:CancelJobRun"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "emr-containers:DescribeJobRun",
          "elasticmapreduce:CreatePersistentAppUI",
          "elasticmapreduce:DescribePersistentAppUI",
          "elasticmapreduce:GetPersistentAppUIPresignedURL"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:Get*",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_security_group" "EMRSecurityGroup" {
  name        = "EMRSparkAI-EMR-SG"
  description = "Security Group for EMRSparkAI-EMR-SecGroup."
  vpc_id      = module.vpc.vpc_id

  revoke_rules_on_delete = true

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      var.vpc_cidr_block,
    ]
  }

  tags = {
    Name = "EMRSparkAI-EMR-SG"
  }
}

resource "aws_security_group" "EMRServiceAccessSecurityGroup" {
  name        = "EMRSparkAI-EMR-ServiceAccess-SG"
  description = "Security Group for EMRSparkAI-EMR-SecGroup"
  vpc_id      = module.vpc.vpc_id

  revoke_rules_on_delete = true

  ingress {
    from_port       = 9443
    to_port         = 9443
    protocol        = "tcp"
    security_groups = [aws_security_group.EMRSecurityGroup.id]
  }

  egress {
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.EMRSecurityGroup.id]
  }

  tags = {
    Name = "EMRSparkAI-EMR-ServiceAccess-SG"
  }
}

resource "aws_security_group" "WorkspaceSecurityGroup" {
  name        = "EMRSparkAI-Workspace-SG"
  description = "Security group for EMR Studio Workspace"
  vpc_id      = module.vpc.vpc_id

  revoke_rules_on_delete = true

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 18888
    to_port         = 18888
    protocol        = "tcp"
    security_groups = [aws_security_group.ClusterEndpointSecurityGroup.id]
  }

  tags = {
    Name                                     = "EMRSparkAI-Workspace-SG"
    for-use-with-amazon-emr-managed-policies = "true"
  }
}

resource "aws_security_group" "ClusterEndpointSecurityGroup" {
  name        = "EMRSparkAI-Cluster-Endpoint-SG"
  description = "Security group for EMR Studio Cluster-Endpoint"
  vpc_id      = module.vpc.vpc_id

  revoke_rules_on_delete = true

  ingress {
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.EMRSecurityGroup.id]
  }

  ingress {
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.EMRServiceAccessSecurityGroup.id]
  }

  tags = {
    Name                                     = "EMRSparkAI-Cluster-Endpoint-SG"
    for-use-with-amazon-emr-managed-policies = "true"
  }
}

resource "aws_security_group_rule" "ClusterEndpointSecurityGroupIngress" {
  security_group_id        = aws_security_group.ClusterEndpointSecurityGroup.id
  protocol                 = "tcp"
  from_port                = 18888
  to_port                  = 18888
  type                     = "ingress"
  source_security_group_id = aws_security_group.WorkspaceSecurityGroup.id
}

resource "aws_iam_role" "EMRDefaultRole" {
  name = "EMR_SparkAI_DefaultRole"

  assume_role_policy = jsonencode({
    Version = "2008-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "elasticmapreduce.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"]
}

resource "aws_iam_role" "EMREC2DefaultRole" {
  name = "EMR_EC2_SparkAI_DefaultRole"

  assume_role_policy = jsonencode({
    Version = "2008-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"]
}

resource "aws_iam_role" "EMRNotebooksDefaultRole" {
  name = "EMR_Notebooks_SparkAI_DefaultRole"

  assume_role_policy = jsonencode({
    Version = "2008-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "elasticmapreduce.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceEditorsRole",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess"
  ]
}

resource "aws_iam_instance_profile" "EMREC2DefaultRoleInstanceProfile" {
  name = "EMR_EC2_SparkAI_DefaultRole"
  path = "/"
  role = aws_iam_role.EMREC2DefaultRole.name
}

resource "aws_emr_cluster" "EMRCluster" {
  name = "spark-custom-python-3.9.18-bedrock"

  depends_on = [
    aws_iam_role.EMRDefaultRole,
    aws_iam_instance_profile.EMREC2DefaultRoleInstanceProfile,
    aws_iam_role.EMREC2DefaultRole
  ]

  master_instance_group {
    instance_count = 1
    instance_type  = "m4.2xlarge"
    name           = "cfnMaster"
  }

  core_instance_group {
    instance_count = 2
    instance_type  = "m4.2xlarge"
    name           = "cfnCore"
  }

  ec2_attributes {
    subnet_id        = module.vpc.public_subnets[0]
    instance_profile = aws_iam_instance_profile.EMREC2DefaultRoleInstanceProfile.arn
  }

  bootstrap_action {
    name = "PythonBedrockLibs"
    path = "s3://aws-blogs-artifacts-public/artifacts/BDB-3655/install-python-bedrock.sh"
  }

  applications = ["Spark", "Livy", "JupyterEnterpriseGateway"]

  configurations = <<EOF
  [
    {
      "Classification" : "spark-hive-site",
      "Properties" : {
        "hive.metastore.client.factory.class" : "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory"
      }
    }
  ]
  EOF

  service_role = aws_iam_role.EMRDefaultRole.arn

  release_label        = "emr-6.12.0"
  visible_to_all_users = true
  log_uri              = "s3://emr-sparkai-${data.aws_caller_identity.current.account_id}/elasticmapreduce/"
}

resource "aws_codecommit_repository" "EMRStudioRepo" {
  repository_name = "EMRStudioSparkAIDemoRepo"
  description     = "This is a repository for EMR Studio Developer Exp workshop."
}
