"""
##            ## ## ## ##
 ##          ##        ##
  ##        ##         ##
   ##      ## ## ## ## ##
    ##    ##
     ##  ##
       ##

AUTHOR = Vimal Paliwal <hello@vimalpaliwal.com>
"""

import sys
import boto3
import click
import threading
from botocore.exceptions import ClientError

from secureaws import checkaws
from secureaws import setupaws
from secureaws import rsautil

# Important Variables - DO NOT change the values
REGION = {
    "N_VIRGINIA": "us-east-1",
    "OHIO": "us-east-2",
    "N_CALIFORNIA": "us-west-1",
    "OREGON": "us-west-2",
    "MUMBAI": "ap-south-1",
    "SEOUL": "ap-northeast-2",
    "SINGAPORE": "ap-southeast-1",
    "SYDNEY": "ap-southeast-2",
    "TOKYO": "ap-northeast-1",
    "CANADA": "ca-central-1",
    "FRANKFURT": "eu-central-1",
    "IRELAND": "eu-west-1",
    "LONDON": "eu-west-2",
    "PARIS": "eu-west-3",
    "SAO_PAULO": "sa-east-1",
    "BAHRAIN": "me-south-1",
    "STOCKHOLM": "eu-north-1",
    "HONG_KONG": "ap-east-1"
}

class secureaws:
    region = ""
    session = None

    def __init__(self, access_key="", secret_key="", profile="", region=""):
        self.region = region
        try:
            if access_key == "" and secret_key == "" and profile == "":
                self.session = boto3.Session(region_name=region)
            elif profile != "":
                self.session = boto3.Session(profile_name=profile, region_name=region)
            elif access_key != "" and secret_key != "":
                self.session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        except Exception as e:
            print("Error: {}".format(e))
            exit(1)

    def getSession(self):
        return self.session

# Managing CLI
@click.group()
def chk_group():
    pass

@chk_group.command()
@click.option('--access-key', help='AWS IAM User Access Key')
@click.option('--secret-key', help='AWS IAM User Access Key')
@click.option('--profile', help='AWS CLI profile')
@click.option('--region', default='us-east-1', help='AWS region identifier. Default: us-east-1')
def check(access_key, secret_key, profile, region):
    '''
    This command will scan your AWS account to identify whether basic security services are enabled or not.
    
    \b
    IAM Policy:
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

    \b
    Usage:
    - Scan AWS account using profile:
        secureaws check --profile xxx --region xxx
    - Scan AWS account using keys:
        secureaws check --access-key xxx --secret-key xxx --region xxx
    '''
    
    secureaws_obj = secureaws(access_key, secret_key, profile, region)
    checkaws.check_account(secureaws_obj.getSession())

@click.group()
def setup_group():
    pass

@setup_group.command()
@click.option('--menu', is_flag=True, help='Display interactive menu to setup security services')
@click.option('--access-key', help='AWS IAM User Access Key')
@click.option('--secret-key', help='AWS IAM User Access Key')
@click.option('--profile', help='AWS CLI profile')
@click.option('--region', default='us-east-1', help='AWS region identifier. Default: us-east-1')
@click.option('--yes', '-y', 'non_interactive', is_flag=True, help='Non-interactive mode')
@click.option('--service', '-s', 'svc', multiple=True, help='Specific service name to setup')
@click.option('--bucket-name', multiple=True, help='Bucket name to encrypt. Only applicable for s3-sse')
@click.option('--instance-id', multiple=True, help='Instance ID (Required only for ebs-sse)')
@click.option('--volume-id', multiple=True, help='Volume ID (Required only for ebs-sse)')
@click.option('--kms-id', help='Supports both KMS Key ID or Alias. Only supported for s3-sse and ebs-sse')
def setup(menu, access_key, secret_key, profile, region, non_interactive, svc, bucket_name, instance_id, volume_id, kms_id):
    '''
    \b
    This command supports securing following services on your AWS account:
    - CloudTrail
    - Config
    - Flow Logs
    - MFA (Default User: root)
    - S3 SSE (Default: AES256)
    - EBS SSE (Default: aws/ebs)
    - Password Policy
    
    \b
    It is recommended to further restrict down the policy as per your need.
    IAM Policy:
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
                    "ec2:DeleteVolume",
                    "ec2:DeleteSnapshot"
                ],
                "Resource": "*"
            }
        ]
    }

    \b
    Service Names:
    - cloudtrail
    - config
    - flowlogs
    - mfa
    - s3-sse
    - ebs-sse
    - password-policy

    \b
    Usage:
    - Setup all services using AWS profile:
        secureaws setup --profile xxx --region xxx
    - Setup all services using AWS keys in non-interactive mode (except ebs-sse):
        secureaws setup --access-key xxx --secret-key xxx --region xxx -y
    - Setup specific service(s):
        secureaws setup --profile xxx --service cloudtrail -s flowlogs -s mfa --region xxx
    - Setup MFA for an Root user:
        secureaws setup --profile xxx -s mfa
    - Setup MFA for an IAM user:
        secureaws setup --profile xxx -s mfa=username
    - Encrypt all S3 buckets using KMS Key ID:
        secureaws setup --profile xxx --region xxx -s s3-sse --kms-id xxx
    - Encrypt specific S3 buckets using default encryption:
        secureaws setup --profile xxx --region xxx -s s3-sse --bucket-name xxx --bucket-name xxx
    - Encrypt EBS Volumes using Instance ID(s):
        secureaws setup --profile xxx -s ebs-sse --instance-id xxx --region xxx
    - Encrypt EBS Volumes using Volume ID(s) and KMS Alias:
        secureaws setup --profile xxx -s ebs-sse --volume-id xxx --volume-id xxx --kms-id alias/xxx --region xxx
    '''

    secureaws_obj = secureaws(access_key, secret_key, profile, region)
    if menu:
        setupaws.secure_account_menu(secureaws_obj.getSession())
    else:
        setupaws.secure_account(secureaws_obj.getSession(), svc, buckets=bucket_name, instance_id=instance_id, volume_id=volume_id, kms_id=kms_id, non_interactive=non_interactive)

@click.group()
def rsa_group():
    pass

@rsa_group.command()
@click.option('--file-name', help='File name for private and public key')
@click.option('--key-size', default=4096, help='Key size (Default: 4096)')
def genrsa(file_name, key_size):
    '''
    This will generate RSA key pair
    '''
    rsautil.create_rsa_key_pair(file_name, key_size)

# Map all click groups
sa = click.CommandCollection(sources=[chk_group,setup_group,rsa_group])

def main():
    sa()

if __name__ == '__main__':
    sa()
