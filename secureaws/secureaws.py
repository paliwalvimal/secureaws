"""
##            ###########
 ##          ##        ##
  ##        ##         ##
   ##      ##############
    ##    ##
     ##  ##
       ##

AUTHOR = Vimal Paliwal <hello@vimalpaliwal.com>
"""

import sys
import boto3
import json
import random
import secrets
import click
from pathlib import Path
from PIL import Image
from botocore.exceptions import ClientError

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

    def menu(self):
        while True:
            print("\nMain Menu:")
            print("====================")
            print("q: Quit")
            print("1: Check Account")
            print("2: Secure Account")
            print("3: Create RSA Key Pair")
            choice = str.lower(str.strip(input("Choice: ")))
            
            if choice == "1":
                self.check_account()
            elif choice == "2":
                self.secure_account_menu()
            elif choice == "3":
                create_rsa_key_pair()
            elif choice == "q":
                print("Thanks for choosing secureaws.\n")
                break
            else:
                print("Invalid choice")
    
    def check_account(self):
        """
        This will check if your account has basic security turned on or not.
        """

        try:
            sys.stdout.write("Checking CloudTrail... ")
            sys.stdout.flush()
            chk = self.check_cloudtrail()
            print("Enabled") if chk == True else print(chk)

            sys.stdout.write("Checking Config... ")
            sys.stdout.flush()
            chk = self.check_config()
            print("Enabled") if chk == True else print(chk)

            sys.stdout.write("Checking Flow Logs... ")
            sys.stdout.flush()
            chk = self.check_flowlogs()
            print("Enabled") if chk == True else print(chk)

            sys.stdout.write("Checking Root MFA... ")
            sys.stdout.flush()
            chk = self.check_root_mfa()
            print("Enabled") if chk == True else print(chk)

            sys.stdout.write("Checking Password Policy... ")
            sys.stdout.flush()
            chk = self.check_custom_password_policy()
            print("Passed") if chk == True else print(chk)

            sys.stdout.write("Checking Macie... ")
            sys.stdout.flush()
            chk = self.check_macie()
            print("Passed") if chk == True else print(chk)

            sys.stdout.write("Checking GuardDuty... ")
            sys.stdout.flush()
            chk = self.check_guard_duty()
            print("Passed") if chk == True else print(chk)

            print("=============================")
            print("Checking S3 Bucket Encryption")
            print("=============================")
            self.check_s3_buckets()

            print("==============================")
            print("Checking EC2 Volume Encryption")
            print("==============================")
            self.check_ec2_volumes()

            return True
        except ClientError as e:
            print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
            return False
        except Exception as ex:
            return "Error: {}".format(ex)

    def check_cloudtrail(self):
        """
        This will check if CloudTrail is enabled

        IAM Permission Required:
            - cloudtrail:DescribeTrails
        """
        
        try:
            cloudtrail = self.session.client('cloudtrail')
            resp = cloudtrail.describe_trails()
            if len(resp['trailList']) > 0:
                return True
            else:
                return "Disabled"
        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)

    def check_config(self):
        """
        This will check if Config is enabled

        IAM Permission Required:
            - config:DescribeConfigurationRecorderStatus
        """

        try:
            config = self.session.client('config')
            resp = config.describe_configuration_recorder_status()
            if len(resp['ConfigurationRecordersStatus']) > 0:
                return True
            else:
                return "Disabled"
        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)

    def check_flowlogs(self):
        """
        This will check if network flow logs are enabled

        IAM Permission Required:
            - ec2:DescribeFlowLogs
        """

        try:
            ec2 = self.session.client('ec2')
            resp = ec2.describe_flow_logs()
            if len(resp['FlowLogs']) > 0:
                return True
            else:
                return "Disabled"
        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)

    def check_root_mfa(self):
        """
        This will check if MFA for root account is enabled

        IAM Permission Required:
            - iam:GetAccountSummary
        """

        try:
            iam = self.session.client('iam')
            resp = iam.get_account_summary()
            if resp['SummaryMap']['AccountMFAEnabled'] == 1:
                return True
            else:
                return "Disabled"
        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)

    def check_custom_password_policy(self):
        """
        This will check if a strong password policy is set

        IAM Permission Required:
            - iam:GetAccountPasswordPolicy
        """

        try:
            iam = self.session.client('iam')
            resp = iam.get_account_password_policy()
            policy = resp['PasswordPolicy']
            if policy['MinimumPasswordLength'] < 8 or policy['RequireSymbols'] == False or policy['RequireNumbers'] == False or policy['RequireUppercaseCharacters'] == False or policy['RequireLowercaseCharacters'] == False or policy['PasswordReusePrevention'] < 3 or policy['ExpirePasswords'] == False or policy['MaxPasswordAge'] > 90:
                return "Failed"
            else:
                return True
        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)

    def check_s3_buckets(self):
        """
        This will check if server-side encryption is enabled for all your S3 buckets

        IAM Permission Required:
            - s3:ListAllMyBuckets
        """

        try:
            failed_buckets = []
            s3 = self.session.client('s3')
            resp = s3.list_buckets()
            for bucket in resp['Buckets']:
                bname = bucket['Name']
                try:
                    sys.stdout.write("{}... ".format(bname))
                    sys.stdout.flush()
                    r = s3.get_bucket_encryption(Bucket=bname)
                    print("Enabled")
                except ClientError as err:
                    print("Disabled")
                    failed_buckets.append(bname)
            
            if len(failed_buckets) > 0:
                return False
            else:
                return True
        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)

    def check_ec2_volumes(self):
        """
        This will check if server-side encryption is enabled for all your EBS volumes

        IAM Permission Required:
            - ec2:DescribeVolumes
        """

        try:
            failed_volumes = []
            ec2 = self.session.client('ec2')
            params = {}
            while True:
                resp = ec2.describe_volumes(**params)
                for volume in resp['Volumes']:
                    vid = volume['VolumeId']
                    vname = self.get_name_tag(volume['Tags']) if "Tags" in volume else None
                    if vname != None:
                        vname = vname + "({})".format(vid)
                    else:
                        vname = vid

                    if volume['Encrypted'] == True:
                        print(vname + "... Enabled")
                    else:
                        failed_volumes.append(vname)
                        print(vname + "... Disabled")
                
                try:
                    params['NextToken'] = resp['NextToken']
                except:
                    break
            
            if len(failed_volumes) > 0:
                return False
            else:
                return True
        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)

    def check_macie(self):
        """
        This will check if Macie is enabled

        IAM Permission Required:
            - macie:ListMemberAccounts
        """
        
        try:
            macie = self.session.client('macie')
            resp = macie.list_member_accounts()
            if len(resp['memberAccounts']) > 0:
                return True
            else:
                return "Disabled"
        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)
    
    def check_guard_duty(self):
        """
        This will check if GuardDuty is enabled

        IAM Permission Required:
            - guardduty:ListDetectors
        """
        
        try:
            guardduty = self.session.client('guardduty')
            resp = guardduty.list_detectors()
            if len(resp['DetectorIds']) > 0:
                return True
            else:
                return "Disabled"

        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)

    def check_bucket_exists(self, bname):
        """
        IAM Permission Required:
            - s3:HeadBucket
        """
        s3 = self.session.client('s3')
        try:
            s3.head_bucket(Bucket=bname)
            return True
        except:
            return False

    def create_s3_bucket(self, bname):
        """
        IAM Permission Required:
            - s3:CreateBucket
        """
        try:
            s3.create_bucket(
                Bucket=bname,
                ACL='private',
                CreateBucketConfiguration={
                    'LocationConstraint': self.region
                }
            )
            return True
        except ClientError as e:
            return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
        except Exception as ex:
            return "Error: {}".format(ex)

    def get_account_id(self):
        """
        IAM Permission Required:
            - sts:GetCallerIdentity
        """
        sts = self.session.client('sts')
        return sts.get_caller_identity()['Account']

    def secure_account_menu(self):
        """
        This will enable basic security services on your AWS account
        """

        try:
            while True:
                print("\nSecure Account Menu:")
                print("====================")
                print("q: Quit")
                print("?: Help")
                print("*: Enable All")
                print("1: Enable CloudTrail")
                print("2: Enable Config")
                print("3: Enable FlowLogs")
                print("4: Enable Root MFA")
                print("5: Enable S3 SSE")
                print("6: Setup Password Policy\n")
                choice = str.lower(str.strip(input("Choice: ")))

                if choice == "q":
                    break
                elif choice == "?":
                    print("=============== HELP ===============")
                    print("To set up individual service simply provide the number referring to the service and hit return key.")
                    print("To set up multiple services simply provide comma(,) seperated numbers referring to the service and hit return key. Example: 2,5,1,3")
                    print("To set up all services provide * and hit return key.")
                elif len(choice.split(",")) > 0:
                    choices = choice.split(",")
                    choices.sort()
                    for ch in choices:
                        if str(ch).strip() == "" or str(ch).isnumeric == False:
                            choices.remove(ch)
                    
                    for ch in choices:
                        if ch == "1":
                            self.enable_cloudtrail()
                        elif ch == "2":
                            self.enable_config()
                        elif ch == "3":
                            self.enable_flowlogs()
                        elif ch == "4":
                            self.setup_virtual_mfa()
                        elif ch == "5":
                            self.enable_s3_sse()
                        elif ch == "6":
                            self.setup_custom_password_policy()
                        elif ch == "q" or ch == "?" or ch == "*":
                            continue
                        else:
                            print("Invalid Choice.")
                elif choice == "*":
                    secure_account()
                elif choice == "1":
                    self.enable_cloudtrail()
                elif choice == "2":
                    self.enable_config()
                elif choice == "3":
                    self.enable_flowlogs()
                elif choice == "4":
                    self.setup_virtual_mfa()
                elif choice == "5":
                    self.enable_s3_sse()
                elif choice == "6":
                    self.setup_custom_password_policy()
                else:
                    print("Invalid choice.")
        except ClientError as e:
            print("Fail. Reason: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
            return False

    def secure_account(self, svc, non_interactive=False):
        if len(svc) == 0:
            self.enable_cloudtrail(non_interactive)
            self.enable_config(non_interactive)
            self.enable_flowlogs(non_interactive)
            self.setup_virtual_mfa(non_interactive)
            self.enable_s3_sse(non_interactive)
            self.setup_custom_password_policy(non_interactive)
        else:
            for s in svc:
                if s == "cloudtrail":
                    self.enable_cloudtrail(non_interactive)
                elif s == "config":
                    self.enable_config(non_interactive)
                elif s == "flowlogs":
                    self.enable_flowlogs(non_interactive)
                elif s == "mfa" or "mfa=" in s:
                    uname = "root" if "=" not in s else s.split("=")[1]
                    self.setup_virtual_mfa(non_interactive, uname)
                elif s == "s3-sse":
                    self.enable_s3_sse(non_interactive)
                elif s == "password-policy":
                    self.setup_custom_password_policy(non_interactive)
    
    def enable_cloudtrail(self, non_interactive):
        """
        This will create a new S3 bucket and enable CloudTrail service for all regions along with recording global events
        """

        opt = ""
        bname = ""
        try:
            print("\n====================================")
            print("Setting up CloudTrail")
            print("====================================")
            if not non_interactive:
                print("Following additional resource will be created:")
                print("> S3 Bucket - To store audit logs")
                
                opt = str.lower(str.strip(input("\nDo you want to continue(Y/n): ")))
            else:
                opt = "y"
                bname = "cloudtrail-all-regions-{}".format(self.random_string(5))

            if opt == "y" or opt == "":
                # Fetching Account ID for S3 Policy and Starting CloudTrail log
                accountId = self.get_account_id()

                bname = str.lower(str.strip(input("Bucket Name: "))) if bname == "" else bname
                
                # Checking if bucket already exists
                sys.stdout.write("Checking if bucket exists... ")
                sys.stdout.flush()
                s3 = self.session.client('s3')
                if self.check_bucket_exists(bname):
                    print("True")
                else:
                    print("False")
                    sys.stdout.write("Creating bucket... ")
                    sys.stdout.flush()
                    cbresp = self.create_s3_bucket(bname)
                    if cbresp:
                        print("Ok ({})".format(bname))
                    else:
                        print(cbresp)
                        return False
                
                # Updating bucket policy
                sys.stdout.write("Assigning permission to bucket... ")
                sys.stdout.flush()
                try:
                    bpolicy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "cloudtrail.amazonaws.com"
                                },
                                "Action": "s3:GetBucketAcl",
                                "Resource": "arn:aws:s3:::{}".format(bname)
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "cloudtrail.amazonaws.com"
                                },
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::{}/AWSLogs/{}/*".format(bname, accountId),
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control"
                                    }
                                }
                            }
                        ]
                    }
                    s3.put_bucket_policy(
                        Bucket=bname,
                        Policy=json.dumps(bpolicy)
                    )
                    print("Ok")
                except ClientError as err:
                    print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
                    return False

                # Setting up CloudTrail
                try:
                    sys.stdout.write("Setting up CloudTrail... ")
                    sys.stdout.flush()
                    trail = self.session.client('cloudtrail')
                    trailName = "all-regions-trail-{}".format(self.random_string(5))
                    tresp = trail.create_trail(
                        Name=trailName,
                        S3BucketName=bname,
                        IncludeGlobalServiceEvents=True,
                        IsMultiRegionTrail=True,
                        EnableLogFileValidation=True
                    )

                    tresp = trail.start_logging(
                        Name="arn:aws:cloudtrail:{}:{}:trail/{}".format(self.region, accountId, trailName)
                    )
                    print("Ok ({})".format(trailName))
                    return True
                except ClientError as err:
                    print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
                    return False
            else:
                print("Skipping CloudTrail setup.")
                return False
        except ClientError as e:
            print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
            return False
        except Exception as ex:
            print("Error: {}".format(ex))
            return False
    
    def enable_config(self, non_interactive):
        """
        This will create a new S3 bucket and enable Config service for specific region
        """

        opt = ""
        bname = ""
        try:
            print("\n====================================")
            print("Setting up Config")
            print("====================================")
            if not non_interactive:
                print("Following additional resource will be created:")
                print("> S3 Bucket - To store configuration snapshots")

                opt = str.lower(str.strip(input("\nDo you want to continue(Y/n): ")))
            else:
                opt = "y"
                bname = "config-{}-{}".format(self.region, self.random_string(5))

            if opt == "" or opt == "y":
                # Fetching Account ID for S3 Policy and Starting CloudTrail log
                accountId = self.get_account_id()
                
                bname = str.lower(str.strip(input("Bucket Name: "))) if bname == "" else bname

                # Checking if bucket exists
                sys.stdout.write("Checking if bucket exists... ")
                sys.stdout.flush()
                s3 = self.session.client('s3')
                if self.check_bucket_exists(bname):
                        print("True")
                else:
                    print("False")
                    sys.stdout.write("Creating bucket... ")
                    sys.stdout.flush()
                    cbresp = self.create_s3_bucket(bname)
                    if cbresp == True:
                        print("Ok ({})".format(bname))
                    else:
                        print(cbresp)
                        return False

                # Updating bucket policy
                sys.stdout.write("Assigning permission to bucket... ")
                sys.stdout.flush()
                try:
                    bpolicy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSConfigBucketPermissionsCheck",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "config.amazonaws.com"
                                },
                                "Action": "s3:GetBucketAcl",
                                "Resource": "arn:aws:s3:::{}".format(bname)
                            },
                            {
                                "Sid": "AWSConfigBucketDelivery",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "config.amazonaws.com"
                                },
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::{}/AWSLogs/{}/Config/*".format(bname, accountId),
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control"
                                    }
                                }
                            }
                        ]
                    }
                    s3.put_bucket_policy(
                        Bucket=bname,
                        Policy=json.dumps(bpolicy)
                    )
                    print("Ok")
                except ClientError as err:
                    print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
                    return False

                # Creating IAM role for Config
                try:
                    sys.stdout.write("Creating IAM role for Config... ")
                    sys.stdout.flush()
                    
                    iam = self.session.client('iam')
                    trust_policy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "config.amazonaws.com"
                            },
                            "Action": "sts:AssumeRole"
                            }
                        ]
                    }
                    roleName = "config-{}-role-{}".format(self.region, self.random_string(5))
                    iresp = iam.create_role(
                        RoleName=roleName,
                        AssumeRolePolicyDocument=json.dumps(trust_policy),
                    )
                    configRoleArn = iresp['Role']['Arn']
                    
                    iam.attach_role_policy(
                        RoleName=roleName,
                        PolicyArn='arn:aws:iam::aws:policy/aws-service-role/AWSConfigServiceRolePolicy'
                    )
                    print("Ok ({})".format(roleName))
                except ClientError as err:
                    print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
                    return False
                
                # Setting up Config
                try:
                    sys.stdout.write("Setting up Config... ")
                    sys.stdout.flush()
                    config = self.session.client('config')
                    recorder_name = 'config-{}-recorder-{}'.format(self.region, self.random_string(5))
                    
                    cresp = config.put_configuration_recorder(
                        ConfigurationRecorder={
                            'name': recorder_name,
                            'roleARN': configRoleArn,
                            'recordingGroup': {
                                'allSupported': True,
                                'includeGlobalResourceTypes': True
                            }
                        }
                    )

                    cresp = config.put_delivery_channel(
                        DeliveryChannel={
                            'name': 'config-{}-channel-{}'.format(self.region, self.random_string(5)),
                            's3BucketName': bname
                        }
                    )

                    cresp = config.start_configuration_recorder(
                        ConfigurationRecorderName=recorder_name
                    )

                    print("Ok ({})".format(recorder_name))
                    return True
                except ClientError as err:
                    print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
                    return False
            else:
                print("Skipping cofig setup")
        except ClientError as e:
            print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
            return False
        except Exception as ex:
            print("Error: {}".format(ex))
            return False

    def add_config_rules(self, non_interactive):     # COMING SOON...
        """
        access-key-rotated
        acm-certificate-expiration-check
        alb-http-to-https-redirection-check
        elb-loggin-enabled
        cloud-trail-log-file-validation-enabled
        cloudtrail-enabled
        encrypted-volumes
        root-account-mfa-enabled
        vpc-flow-logs-enabled
        s3-bucket-server-side-encryption-enabled
        """

        try:
            return True
        except ClientError as e:
            print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
            return False
        except Exception as ex:
            print("Error: {}".format(ex))
            return False

    def enable_flowlogs(self, non_interactive):
        """
        This will enable flow logs on all existing VPCs
        """

        opt = ""
        try:
            print("\n====================================")
            print("Setting up FlowLogs")
            print("====================================")

            if not non_interactive:
                print("Following additional resources will be created:")
                print("> IAM Role - Permission for VPC to put logs in CloudWatch")
                print("> CloudWatch Log Group - To store VPC Flow Logs")

                opt = str.lower(str.strip(input("\nDo you want to continue(Y/n): ")))
            else:
                opt = "y"

            if opt == "y" or opt == "":      
                # Creating IAM Role
                sys.stdout.write("Creating IAM Role... ")
                sys.stdout.flush()
                iam = self.session.client('iam')

                trust_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "vpc-flow-logs.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                        }
                    ]
                }
                roleName = "vpc-flow-logs-role-{}".format(self.random_string(5))
                iresp = iam.create_role(
                    RoleName=roleName,
                    AssumeRolePolicyDocument=json.dumps(trust_policy)
                )
                role_arn = iresp['Role']['Arn']

                permission_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:DescribeLogGroups",
                                "logs:DescribeLogStreams",
                                "logs:PutLogEvents"
                            ],
                            "Effect": "Allow",
                            "Resource": "*"
                        }
                    ]
                }
                iresp = iam.create_policy(
                    PolicyName="vpc-flow-logs-policy-{}".format(self.random_string(5)),
                    PolicyDocument=json.dumps(permission_policy)
                )

                iam.attach_role_policy(
                    RoleName=roleName,
                    PolicyArn=iresp['Policy']['Arn']
                )
                print("Ok ({})".format(roleName))

                # Setting up flow logs for all VPCs
                ec2 = self.session.client('ec2')
                vresp = ec2.describe_vpcs()
                for vpc in vresp['Vpcs']:
                    vpc_id = vpc['VpcId']
                    vpc_name = self.get_name_tag(vpc['Tags']) if 'Tags' in vpc else None
                    if vpc_name == None:
                        vpc_name = vpc_id
                    
                    log_group_name = "{}-flow-log-group-{}".format(vpc_name, self.random_string(5))
                    # Creating CloudWatch Log Group
                    sys.stdout.write("Creating CloudWatch Log Group... ")
                    sys.stdout.flush()
                    logs = self.session.client('logs')
                    logs.create_log_group(
                        logGroupName=log_group_name
                    )

                    lresp = logs.describe_log_groups(
                        logGroupNamePrefix=log_group_name,
                        limit=1
                    )
                    log_group_arn = lresp['logGroups'][0]['arn']
                    print("Ok ({})".format(log_group_name))

                    # Starting Flow Logs
                    sys.stdout.write("Starting Flow Logs... ")
                    sys.stdout.flush()
                    ec2 = self.session.client('ec2')
                    eresp = ec2.create_flow_logs(
                        DeliverLogsPermissionArn=role_arn,
                        LogGroupName=log_group_name,
                        ResourceIds=[
                            vpc_id,
                        ],
                        ResourceType='VPC',
                        TrafficType='ALL',
                        LogDestinationType='cloud-watch-logs'
                    )

                    if len(eresp['Unsuccessful']) > 0:
                        print("Fail. Reason:" + eresp['Unsuccessful'][0]['Error']['Code'])
                        return False

                    print("Ok ({})".format(eresp['FlowLogIds'][0]))
                    return True
            else:
                print("Skipping flowlog setup")
                return False

        except ClientError as e:
            print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
            return False
        except Exception as ex:
            print("Error: {}".format(ex))
            return False

    def setup_virtual_mfa(self, non_interactive, username="root"):
        """
        This will setup MFA on root account by default
        """

        opt = ""
        try:
            print("\n====================================")
            print("Setting up MFA")
            print("====================================")
            if not non_interactive:
                uname = str.lower(str.strip(input("Username ({}): ".format(username))))
                username = uname if not str.strip(uname) == "" else username

                print("\nThis will enable MFA on {} user.".format(username))
                opt = str.lower(str.strip(input("Do you want to continue(Y/n): ")))
            else:
                opt = "y"

            if opt == "y" or opt == "":
                # Creating virtual mfa device
                sys.stdout.write("Creating virtual MFA device... ")
                sys.stdout.flush()
                iam = self.session.client('iam')

                rand_num = random.randint(1000, 9999)
                mfa_name = username
                user_path = "/" if username == "root" else "/user/" + username + "/"
                mresp = iam.create_virtual_mfa_device(
                    Path=user_path,
                    VirtualMFADeviceName='{}-mfa-device-{}'.format(mfa_name, rand_num)
                )
                mfa_serial = mresp['VirtualMFADevice']['SerialNumber']
                png_path = str(Path.home()) + "/{}-mfa-qr-{}.png".format(mfa_name, rand_num)
                secret = ""
                try:
                    secret = str(mresp['VirtualMFADevice']['Base32StringSeed'], 'utf-8')
                    with open(png_path, "wb") as f:
                        f.write(mresp['VirtualMFADevice']['QRCodePNG'])
                    
                    img = Image.open(png_path)
                    img.show()
                except IOError as ioerr:
                    return False
                
                print("Ok")
                print("==========================================")
                print("Secret: " + secret)
                print("==========================================")

                print("Open Google Authenticator app on your mobile/tab and scan the QR code or use the secret displayed above to setup MFA for {} user.".format(mfa_name))
                print("Please wait for the code to refresh after first input.")
                for index in range(2):  # Allowing 2 attempts
                    mfa1 = input("Auth Code 1: ")
                    mfa2 = input("Auth Code 2: ")
                    try:
                        maresp = iam.enable_mfa_device(
                            UserName=mfa_name,
                            SerialNumber=mfa_serial,
                            AuthenticationCode1=mfa1,
                            AuthenticationCode2=mfa2
                        )
                        break
                    except ClientError as err:
                        print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
                        if index == 1:
                            print("You have exhausted the limit. Please start the setup again.")
                            return False
                        print("This is your last try.\n")

                print("Virtual MFA has been enabled for {} user.".format(mfa_name))
                return True
            else:
                print("Skipping MFA setup")
        except ClientError as e:
            print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
            return False
        except Exception as ex:
            print("Error: {}".format(ex))
            return False

    def enable_s3_sse(self, non_interactive):
        """
        This will enable server-side encryption on all your S3 buckets
        """

        opt = ""
        try:
            print("\n====================================")
            print("Setting up S3 SSE")
            print("====================================")

            if not non_interactive:
                print("This will enable SSE on all S3 buckets.")
                opt = str.lower(str.strip(input("\nDo you want to continue(Y/n): ")))
            else:
                opt = "y"

            if opt == "y" or opt == "":
                print("===============================")
                print("Enabling SSE for all S3 buckets")
                print("===============================")
                s3 = self.session.client('s3')
                resp = s3.list_buckets()
                for bucket in resp['Buckets']:
                    bname = bucket['Name']
                    try:
                        sys.stdout.write("{}... ".format(bname))
                        sys.stdout.flush()
                        r = s3.put_bucket_encryption(
                                Bucket=bname,
                                ServerSideEncryptionConfiguration={
                                    'Rules': [
                                        {
                                            'ApplyServerSideEncryptionByDefault': {
                                                'SSEAlgorithm': 'AES256'
                                            }
                                        },
                                    ]
                                }
                            )
                        print("Enabled")
                    except ClientError as err:
                        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
                        return False
            else:
                print("Skipping SSE setup on S3 buckets")
        except ClientError as e:
            print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
            return False
        except Exception as ex:
            print("Error: {}".format(ex))
            return False

    def setup_custom_password_policy(self, non_interactive, pass_length=10, rq_num=True, rq_upper=True, rq_lower=True, rq_symbol=True, pass_history=3, pass_age=90):
        """
        This will setup a strong password policy
        """

        opt = ""
        try:
            print("\n====================================")
            print("Setting up Password Policy")
            print("====================================")
            print("Following policy will be created:")
            print("> Minimum Password Length: {}".format(pass_length))
            print("> Require Numbers        : {}".format(rq_num))
            print("> Require Symbols        : {}".format(rq_symbol))
            print("> Require Uppercase      : {}".format(rq_upper))
            print("> Require Lowercase      : {}".format(rq_lower))
            print("> Password History       : Last {}".format(pass_history))
            print("> Password Age           : {} days".format(pass_age))

            if not non_interactive:
                opt = str.lower(str.strip(input("\nDo you want to continue(Y/n): ")))
            else:
                opt = "y"

            if opt == "y" or opt == "":
                sys.stdout.write("Setting up password policy... ")
                sys.stdout.flush()
                
                iam = self.session.client('iam')
                iresp = iam.update_account_password_policy(
                    MinimumPasswordLength=pass_length,
                    RequireSymbols=rq_symbol,
                    RequireNumbers=rq_num,
                    RequireUppercaseCharacters=rq_upper,
                    RequireLowercaseCharacters=rq_lower,
                    MaxPasswordAge=pass_age,
                    PasswordReusePrevention=pass_history
                )
                print("Ok.")
            else:
                print("Skipping password policy setup")

            return True
        except ClientError as e:
            print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
            return False
        except Exception as ex:
            print("Error: {}".format(ex))
            return False

    # Helper functions
    def get_name_tag(self, tags):
        for tag in tags:
            if tag['Key'] == 'Name':
                return tag['Value']
        
        return None
    
    def random_string(self, len):
        return secrets.token_hex()[0:len]

# Utility Function(s)
def create_rsa_key_pair(file_name="", key_size=4096):
    """
    This will generate a new custom RSA key pair
    """

    try:
        secureaws_obj = secureaws()
        sys.stdout.write("Generating Key Pair... ")
        sys.stdout.flush()
        from Cryptodome.PublicKey import RSA

        new_key = RSA.generate(key_size)
        public_key = new_key.publickey().exportKey('OpenSSH')
        private_key = new_key.exportKey()
        
        pvt_file = "private-key-{}.pem".format(secureaws_obj.random_string(5)) if file_name == "" or file_name is None else "{}.pem".format(file_name)
        pub_file = "public-key-{}.pub".format(secureaws_obj.random_string(5)) if file_name == "" or file_name is None else "{}.pub".format(file_name)
        
        file_out = open(pvt_file, "wb")
        file_out.write(private_key)

        file_out = open(pub_file, "wb")
        file_out.write(public_key)

        print("Ok")
        print("Private Key: {}".format(pvt_file))
        print("Public Key: {}".format(pub_file))
        return True
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False

# Managing CLI
@click.group()
def init_group():
    pass

@init_group.command()
@click.option('--access-key', help='AWS IAM User Access Key')
@click.option('--secret-key', help='AWS IAM User Access Key')
@click.option('--profile', help='AWS CLI profile')
@click.option('--region', default='us-east-1', help='AWS region identifier. Default: us-east-1')
def menu(access_key, secret_key, profile, region):
    """
    Displays application menu options.

    Authentication information is required to scan or enable security services for your AWS account.
    """
    secureaws_obj = secureaws(access_key, secret_key, profile, region)
    secureaws_obj.menu()

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
    secureaws_obj.check_account()

@click.group()
def setup_group():
    pass

@setup_group.command()
@click.option('--access-key', help='AWS IAM User Access Key')
@click.option('--secret-key', help='AWS IAM User Access Key')
@click.option('--profile', help='AWS CLI profile')
@click.option('--region', default='us-east-1', help='AWS region identifier. Default: us-east-1')
@click.option('--yes', '-y', 'non_interactive', is_flag=True, help='Non-interactive mode')
@click.option('--service', '-s', 'svc', multiple=True, help='Specific service name to setup')
def setup(access_key, secret_key, profile, region, non_interactive, svc):
    '''
    \b
    This command will setup following security services on your AWS account:
    - CloudTrail
    - Config
    - Flow Logs
    - MFA (Default User: root)
    - S3 SSE (Default: AES256)
    - Password Policy
    
    \b
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
                    "s3:HeadBucket"
                    "cloudtrail:StartLogging",
                    "cloudtrail:CreateTrail",
                    "iam:CreateRole",
                    "iam:AttachRolePolicy",
                    "iam:CreatePolicy",
                    "iam:UpdateAccountPasswordPolicy",
                    "config:StartConfigurationRecorder",
                    "config:PutDeliveryChannel",
                    "config:PutConfigurationRecorder",
                    "logs:CreateLogGroup",
                    "logs:DescribeLogGroups",
                    "ec2:CreateFlowLogs",
                    "ec2:DescribeVpcs",
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
    - password-policy

    \b
    Usage:
    - Setup all services using AWS profile:
        secureaws setup --profile xxx --region xxx
    - Setup all services using AWS keys:
        secureaws setup --access-key xxx --secret-key xxx --region xxx
    - Setup specific service(s):
        secureaws setup --profile xxx --service cloudtrail -s flowlogs -s mfa --region xxx
    - Setup MFA for an IAM user:
        secureaws setup --profile xxx -s mfa=username --region xxx
    '''

    secureaws_obj = secureaws(access_key, secret_key, profile, region)
    secureaws_obj.secure_account(svc, non_interactive)

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
    create_rsa_key_pair(file_name, key_size)

# Map all click groups
sa = click.CommandCollection(sources=[init_group,chk_group,setup_group,rsa_group])

def main():
    sa()

if __name__ == '__main__':
    sa()