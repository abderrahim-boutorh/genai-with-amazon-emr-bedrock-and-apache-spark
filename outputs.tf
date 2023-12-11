output "EMRSparkAIBucket" {
  description = "Bucket that contains content of the workshop"
  value       = "s3://${aws_s3_bucket.EMRSparkAIBucket.bucket}"
}

output "VPCID" {
  description = "VPC Id to be used for EMR Studio"
  value       = module.vpc.vpc_id
}

output "PrivateSubnetID1" {
  description = "Private subnet #1 id"
  value       = module.vpc.private_subnets[0]
}

output "PrivateSubnetID2" {
  description = "Private subnet #2 id"
  value       = module.vpc.private_subnets[1]
}

output "PublicSubnetID1" {
  description = "Public subnet #1 id"
  value       = module.vpc.public_subnets[0]

}

output "PublicSubnetID2" {
  description = "Public subnet #2 id"
  value       = module.vpc.public_subnets[1]

}

output "ServiceRoleARN" {
  description = "Service Role ARN to be used for EMR Studio"
  value       = aws_iam_role.EMRStudioServiceRole.arn
}

output "UserRoleARN" {
  description = "User Role ARN to be used for EMR Studio"
  value       = aws_iam_role.EMRStudioUserRole.arn
}

output "WorkspaceSecGroupID" {
  description = "Workspace sec group id to be used for EMR Studio"
  value       = aws_security_group.WorkspaceSecurityGroup.id
}

output "ClusterEndpointSecGroupId" {
  description = "Cluster/endpoint sec group id to be used for EMR Studio"
  value       = aws_security_group.ClusterEndpointSecurityGroup.id
}

output "AdvanceUserSessionPolicyARN" {
  description = "Advance User Session policy ARN to be used for EMR Studio"
  value       = aws_iam_policy.StudioAdvanceUserSessionPolicy.arn
}

output "IntermediateUserSessionPolicyARN" {
  description = "Intermediate User Session policy ARN to be used for EMR Studio"
  value       = aws_iam_policy.StudioIntermediateUserSessionPolicy.arn
}

output "ConsoleIAMLoginUrl" {
  description = "Console IAM Login URL for test users"
  value       = "https://${data.aws_caller_identity.current.account_id}.signin.aws.amazon.com/console"
}

output "AWSCodeCommitCloneHTTPSURL" {
  description = "AWS CodeCommit HTTPS URL for linking repository to Amazon EMR Studio Workspace"
  value       = aws_codecommit_repository.EMRStudioRepo.clone_url_http
}