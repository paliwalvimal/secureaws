# secure-aws

This package will scan your AWS account to identify whether basic security services are enabled. If not, will help you enable/setup the same.

## Licence:
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

MIT Licence. See [Licence](LICENCE) for full details.

## Covered Services:
- CloudTrail
- Config
- Root MFA
- VPC Flow Logs
- Strong Password Policy
- Macie
- Guardy Duty
- S3 SSE Encryption
- EBS Encryption
- More coming soon...

## Installation (Any 1):
- Run `pip3 install secureaws`
- Clone the repo and run `python3 setup.py install`

## Help:
- `secureaws --help`
- `secureaws <command> --help`

## Examples:
- Scan AWS account using AWS keys: `secureaws check --access-key XXXXXX --secret-key XXXXXX --region us-west-2`
- Scan AWS account using profile: `secureaws check --profile xxx --region eu-west-1`
- Setup all services in interactive mode: `secureaws setup --profile XXXXXX --region ap-south-1`
- Setup all services in non-interactive mode (except ebs-sse): `secureaws setup --access-key XXXXXX --secret-key XXXXXX -y`
- Setup specific service(s): `secureaws setup --profile XXXXXX --region ap-south-1 -s config -s mfa`
- Generate RSA Key Pair: `secureaws genrsa`
- Generate RSA Key Pair with custom filename and key size: `secureaws genrsa --file-name xxx --key-size 2048`

## IAM Permissions required:
#### You can also find required IAM permission under help section of both check and setup.

### For `check` command:
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
          "cloudtrail:DescribeTrails",
          "config:DescribeConfigurationRecorderStatus",
          "ec2:DescribeFlowLogs",
          "iam:GetAccountSummary",
          "iam:GetAccountPasswordPolicy",
          "macie:ListMemberAccounts",
          "guardduty:ListDetectors",
          "s3:ListAllMyBuckets",
          "s3:GetEncryptionConfiguration",
          "ec2:DescribeVolumes"
      ],
      "Resource": "*"
    }
  ]
}
```

### For `setup` command:
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:PutEncryptionConfiguration",
        "s3:ListAllMyBuckets",
        "s3:PutBucketPolicy",
        "s3:HeadBucket",
        "cloudtrail:StartLogging",
        "cloudtrail:CreateTrail",
        "iam:CreateRole",
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:CreatePolicy",
        "iam:UpdateAccountPasswordPolicy",
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "config:StartConfigurationRecorder",
        "config:PutDeliveryChannel",
        "config:PutConfigurationRecorder",
        "logs:CreateLogGroup",
        "logs:DescribeLogGroups",
        "ec2:CreateFlowLogs",
        "ec2:DescribeVpcs",
        "ec2:StopInstances",
        "ec2:StartInstances",
        "ec2:CreateSnapshot",
        "ec2:CopySnapshot",
        "ec2:CreateVolume",
        "ec2:AttachVolume",
        "ec2:DeleteVolume",   # Required for deleting unencrypted volume
        "ec2:DeleteSnapshot"  # Required for deleting unencrypted snapshot
      ],
      "Resource": "*"
    }
  ]
}
```