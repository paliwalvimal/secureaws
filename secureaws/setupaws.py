import random
import json
import time
import sys
import threading
from pathlib import Path
from PIL import Image
from botocore.exceptions import ClientError

from secureaws import common

def secure_account_menu(session):
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
            print("6: Setup Password Policy")
            print("7: Enable EBS SSE\n")
            choice = str.lower(str.strip(input("Choice: ")))

            if choice == "q":
                break
            elif choice == "?":
                print("=============== HELP ===============")
                print("- To set up individual service simply provide the number referring to the service and hit return key.")
                print("- To set up multiple services simply provide comma(,) seperated numbers referring to the service and hit return key. Example: 2,5,1,3")
                print("- To set up all services provide * and hit return key.")
            elif choice == "*":
                secure_account(session, non_interactive=False)
            elif len(choice.split(",")) > 0:
                choices = choice.split(",")
                choices.sort()
                for ch in choices:
                    if str(ch).strip() == "" or str(ch).isnumeric == False:
                        choices.remove(ch)
                
                for ch in choices:
                    if ch == "1":
                        enable_cloudtrail(session, non_interactive=False)
                    elif ch == "2":
                        enable_config(session, non_interactive=False)
                    elif ch == "3":
                        enable_flowlogs(session, non_interactive=False)
                    elif ch == "4":
                        setup_virtual_mfa(session, non_interactive=False)
                    elif ch == "5":
                        enable_s3_sse(session, non_interactive=False)
                    elif ch == "6":
                        setup_custom_password_policy(session, non_interactive=False)
                    elif ch == "7":
                        enable_ebs_sse(session, non_interactive=False)
                    elif ch == "q" or ch == "?" or ch == "*":
                        continue
                    else:
                        print("Invalid Choice.")
            elif choice == "1":
                enable_cloudtrail(session, non_interactive=False)
            elif choice == "2":
                enable_config(session, non_interactive=False)
            elif choice == "3":
                enable_flowlogs(session, non_interactive=False)
            elif choice == "4":
                setup_virtual_mfa(session, non_interactive=False)
            elif choice == "5":
                enable_s3_sse(session, non_interactive=False)
            elif choice == "6":
                setup_custom_password_policy(session, non_interactive=False)
            elif choice == "7":
                enable_ebs_sse(session, non_interactive=False)
            else:
                print("Invalid choice.")
    except ClientError as e:
        print("Fail. Reason: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False

def secure_account(session, svc=None, buckets=None, instance_id=None, volume_id=None, kms_id=None, non_interactive=False):
    if svc == None or len(svc) == 0:
        enable_cloudtrail(session, non_interactive)
        enable_config(session, non_interactive)
        enable_flowlogs(session, non_interactive)
        setup_virtual_mfa(session, non_interactive)
        enable_s3_sse(session, non_interactive, buckets, kms_id)
        setup_custom_password_policy(session, non_interactive)
        if not non_interactive:
            enable_ebs_sse(session, non_interactive, instance_id, volume_id, kms_id)
    else:
        for s in svc:
            if s == "cloudtrail":
                enable_cloudtrail(session, non_interactive)
            elif s == "config":
                enable_config(session, non_interactive)
            elif s == "flowlogs":
                enable_flowlogs(session, non_interactive)
            elif s == "mfa" or "mfa=" in s:
                uname = "root" if "=" not in s else s.split("=")[1]
                setup_virtual_mfa(session, non_interactive, uname)
            elif s == "s3-sse":
                enable_s3_sse(session, non_interactive, buckets, kms_id)
            elif s == "ebs-sse":
                if ((instance_id is None and volume_id is None) or (len(instance_id) == 0 and len(volume_id) == 0)) and non_interactive:
                    print("Either --instance-id or --volume-id is required for EBS enryption")
                    return False
                enable_ebs_sse(session, non_interactive, instance_id, volume_id, kms_id)
            elif s == "password-policy":
                setup_custom_password_policy(session, non_interactive)

def enable_cloudtrail(session, non_interactive):
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
            bname = "cloudtrail-all-regions-{}".format(common.random_string(5))

        if opt == "y" or opt == "":
            # Fetching Account ID for S3 Policy and Starting CloudTrail log
            accountId = common.get_account_id()

            bname = str.lower(str.strip(input("Bucket Name: "))) if bname == "" else bname
            
            # Checking if bucket already exists
            sys.stdout.write("Checking if bucket exists... ")
            sys.stdout.flush()
            s3 = session.client('s3')
            if common.check_bucket_exists(bname):
                print("True")
            else:
                print("False")
                sys.stdout.write("Creating bucket... ")
                sys.stdout.flush()
                cbresp = common.create_s3_bucket(bname, session.region_name)
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
                    time.sleep(1)
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
                    trail = session.client('cloudtrail')
                    trailName = "all-regions-trail-{}".format(common.random_string(5))
                    tresp = trail.create_trail(
                        Name=trailName,
                        S3BucketName=bname,
                        IncludeGlobalServiceEvents=True,
                        IsMultiRegionTrail=True,
                        EnableLogFileValidation=True
                    )

                    tresp = trail.start_logging(
                        Name="arn:aws:cloudtrail:{}:{}:trail/{}".format(session.region_name, accountId, trailName)
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

def enable_config(session, non_interactive):
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
            bname = "config-{}-{}".format(session.region_name, common.random_string(5))

        if opt == "" or opt == "y":
            # Fetching Account ID for S3 Policy and Starting CloudTrail log
            accountId = common.get_account_id()
            
            bname = str.lower(str.strip(input("Bucket Name: "))) if bname == "" else bname

            # Checking if bucket exists
            sys.stdout.write("Checking if bucket exists... ")
            sys.stdout.flush()
            s3 = session.client('s3')
            if common.check_bucket_exists(bname):
                print("True")
            else:
                print("False")
                sys.stdout.write("Creating bucket... ")
                sys.stdout.flush()
                cbresp = common.create_s3_bucket(bname, session.region_name)
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
                    time.sleep(1)
                    s3.put_bucket_policy(
                        Bucket=bname,
                        Policy=json.dumps(bpolicy)
                    )
                    print("Ok")
                except ClientError as err:
                    print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
                    return False
                
                # Setting up Config
                try:
                    sys.stdout.write("Setting up Config... ")
                    sys.stdout.flush()
                    config = session.client('config')
                    recorder_name = 'config-{}-recorder-{}'.format(session.region_name, common.random_string(5))
                    
                    cresp = config.put_configuration_recorder(
                        ConfigurationRecorder={
                            'name': recorder_name,
                            'roleARN': "arn:aws:iam::{}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig".format(accountId),
                            'recordingGroup': {
                                'allSupported': True,
                                'includeGlobalResourceTypes': True
                            }
                        }
                    )

                    cresp = config.put_delivery_channel(
                        DeliveryChannel={
                            'name': 'config-{}-channel-{}'.format(session.region_name, common.random_string(5)),
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

def add_config_rules(session, non_interactive):     # COMING SOON...
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

def enable_flowlogs(session, non_interactive):
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
            iam = session.client('iam')

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
            roleName = "vpc-flow-logs-role-{}".format(common.random_string(5))
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
                PolicyName="vpc-flow-logs-policy-{}".format(common.random_string(5)),
                PolicyDocument=json.dumps(permission_policy)
            )

            iam.attach_role_policy(
                RoleName=roleName,
                PolicyArn=iresp['Policy']['Arn']
            )
            print("Ok ({})".format(roleName))

            # Setting up flow logs for all VPCs
            ec2 = session.client('ec2')
            vresp = ec2.describe_vpcs()
            for vpc in vresp['Vpcs']:
                vpc_id = vpc['VpcId']
                vpc_name = common.get_name_tag(vpc['Tags']) if 'Tags' in vpc else None
                if vpc_name == None:
                    vpc_name = vpc_id
                
                log_group_name = "{}-flow-log-group-{}".format(vpc_name, common.random_string(5))
                # Creating CloudWatch Log Group
                sys.stdout.write("Creating CloudWatch Log Group... ")
                sys.stdout.flush()
                logs = session.client('logs')
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
                ec2 = session.client('ec2')
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

def setup_virtual_mfa(session, non_interactive, username="root"):
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
            if username != "root":
                # Checking if user exists
                iam = session.client('iam')
                sys.stdout.write("Checking if user exists... ")
                sys.stdout.flush()
                try:
                    uresp = iam.get_user(
                        UserName=username
                    )
                    print("Ok")
                except ClientError as err:
                    if err.response['Error']['Code'] == "NoSuchEntity":
                        print("False")
                    else:
                        print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
                    return False

            # Checking if MFA is already enabled for user
            iam = session.client('iam')
            sys.stdout.write("Checking if MFA already enabled... ")
            sys.stdout.flush()
            try:
                uresp = iam.list_mfa_devices(
                    UserName=username
                )
                if len(uresp['MFADevices']) > 0:
                    print("True")
                    return False
                print("False")
            except ClientError as err:
                print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
                return False

            # Creating virtual mfa device
            sys.stdout.write("Creating virtual MFA device... ")
            sys.stdout.flush()

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

def enable_s3_sse(session, non_interactive, buckets=None, kms_id=None):
    """
    This will enable server-side encryption on all your S3 buckets
    """

    opt = ""
    try:
        if not non_interactive:
            print("\n====================================")
            print("Setting up S3 SSE")
            print("====================================")

            print("This will enable SSE on all S3 buckets.")
            opt = str.lower(str.strip(input("\nDo you want to continue(Y/n): ")))
        else:
            opt = "y"

        if opt == "y" or opt == "":
            s3 = session.client('s3')
            if buckets == None or len(buckets) == 0:
                resp = s3.list_buckets()
                bucket_list = resp['Buckets']
            else:
                bucket_list = []
                for b in list(buckets):
                    tmp = {
                        'Name': b
                    }
                    bucket_list.append(tmp)

            for bucket in bucket_list:
                bname = bucket['Name']
                try:
                    sys.stdout.write("{}... ".format(bname))
                    sys.stdout.flush()
                    args = {
                        'Bucket': bname,
                        'ServerSideEncryptionConfiguration': {
                            'Rules': []
                        }
                    }
                    if kms_id == None or len(kms_id) == 0:
                        args['ServerSideEncryptionConfiguration']['Rules'].append({
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        })
                    else:
                        args['ServerSideEncryptionConfiguration']['Rules'].append({
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'aws:kms',
                                'KMSMasterKeyID': common.prepare_kms_key(session, kms_id)
                            }
                        })
                    r = s3.put_bucket_encryption(**args)
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

def setup_custom_password_policy(session, non_interactive, pass_length=10, rq_num=True, rq_upper=True, rq_lower=True, rq_symbol=True, pass_history=3, pass_age=90):
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
            
            iam = session.client('iam')
            iresp = iam.update_account_password_policy(
                MinimumPasswordLength=pass_length,
                RequireSymbols=rq_symbol,
                RequireNumbers=rq_num,
                RequireUppercaseCharacters=rq_upper,
                RequireLowercaseCharacters=rq_lower,
                MaxPasswordAge=pass_age,
                PasswordReusePrevention=pass_history
            )
            print("Ok")
        else:
            print("Skipping password policy setup")

        return True
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False

def enable_ebs_sse(session, non_interactive, instance_ids=None, volume_ids=None, kms_id=None):
    """
    This will enable server-side encryption on EBS volumes
    """

    opt = ""
    try:
        print("\n====================================")
        print("Encrypting EBS Volumes")
        print("====================================")

        print("!!!WARNING!!!\nThis results in downtime if volume is attached to an instance.")
        if not non_interactive:
            vm_ids = str.lower(str.strip(input("\nEnter instance id(s)(comma separated): ")))
            vol_ids = str.lower(str.strip(input("Enter volume id(s)(comma separated): ")))

            if len(vm_ids) < 10 and len(vol_ids) < 10:
                print("Either instance id or volume id is required.")
                return False
            
            if len(vm_ids) > 10:
                instance_ids = tuple(str(s).strip(", ") for s in vm_ids.strip(", ").split(","))
            if len(vol_ids) > 10:
                volume_ids = tuple(str(s).strip(", ") for s in vol_ids.strip(", ").split(","))

            opt = str.lower(str.strip(input("\nDo you want to continue(Y/n): ")))
        else:
            opt = "y"

        if opt == "y" or opt == "":
            ec2 = session.client('ec2')
            final_list = {}

            params = {}
            if instance_ids != None and len(instance_ids) > 0:
                params['Filters'] = [
                    {
                        'Name': 'attachment.instance-id',
                        'Values': list(instance_ids)
                    }
                ]
                while True:
                    resp = ec2.describe_volumes(**params)
                    for volume in resp['Volumes']:
                        unique = True

                        if volume['Attachments'][0]['InstanceId'] not in final_list:
                            final_list[volume['Attachments'][0]['InstanceId']] = []
                        else:
                            for vol in final_list[volume['Attachments'][0]['InstanceId']]:
                                if volume['VolumeId'] == vol['VolumeId']:
                                    unique = False
                                    break
                        
                        if unique:
                            tmp = {
                                'VolumeId': volume['VolumeId'],
                                'Encrypted': volume['Encrypted'],
                                'MountPath': volume['Attachments'][0]['Device'],
                                'AZ': volume['AvailabilityZone'],
                                'VolumeType': volume['VolumeType']
                            }
                            if 'Iops' in volume:
                                tmp['Iops'] = volume['Iops']
                            if 'Tags' in volume:
                                tmp['Tags'] = volume['Tags']

                            final_list[volume['Attachments'][0]['InstanceId']].append(tmp)
                    try:
                        params['NextToken'] = resp['NextToken']
                    except:
                        break
            
            params = {}
            if volume_ids != None and len(volume_ids) > 0:
                params['VolumeIds'] = list(volume_ids)
                while True:
                    resp = ec2.describe_volumes(**params)
                    for volume in resp['Volumes']:
                        vm_id = 'null' if len(volume['Attachments']) == 0 else volume['Attachments'][0]['InstanceId']
                        unique = True

                        if vm_id not in final_list:
                            final_list[vm_id] = []
                        else:
                            for vol in final_list[vm_id]:
                                if volume['VolumeId'] == vol['VolumeId']:
                                    unique = False
                                    break
                        
                        if unique:
                            tmp = {
                                'VolumeId': volume['VolumeId'],
                                'Encrypted': volume['Encrypted'],
                                'AZ': volume['AvailabilityZone'],
                                'VolumeType': volume['VolumeType']
                            }
                            if 'Iops' in volume:
                                tmp['Iops'] = volume['Iops']
                            if 'Tags' in volume:
                                tmp['Tags'] = volume['Tags']
                            if len(volume['Attachments']) != 0:
                                tmp['MountPath'] = volume['Attachments'][0]['Device']

                            final_list[vm_id].append(tmp)
                    try:
                        params['NextToken'] = resp['NextToken']
                    except:
                        break
            
            manage_ebs_encryption(session, final_list, kms_id)
        else:
            print("Skipping EBS Volume Encryption")
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False

def manage_ebs_encryption(session, volume_list, kms_id):
    # print(volume_list)
    for vmid in volume_list:
        if vmid != "null":
            print("Starting encryption process for volume(s) belonging to instance {}".format(vmid))
            stop_instance(session, vmid)
        
        threads = []
        for vol in volume_list[vmid]:
            t = threading.Thread(target=start_sse_process, args=(session,vmid,vol,kms_id,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
        
        if vmid != "null":
            print("Volume(s) belonging to instance {} were successfully encrypted".format(vmid))
            start_instance(session, vmid)

def start_sse_process(session, vmid, vol, kms_id):
    if vol['Encrypted'] == True:
        print("Volume {} is already encrypted. Skipping encryption process.".format(vol['VolumeId']))
        return False
    else:
        print("Starting encryption of volume {}".format(vol['VolumeId']))
        
        # Step 1: Create snapshot
        old_snap_id = create_snapshot(session, vol['VolumeId'])
        if old_snap_id == False:
            print("Snapshot creation failed for volume {}".format(vol['VolumeId']))
            return False

        # Step 2: Clone snapshot with encryption
        if kms_id == None or len(kms_id) == 0:
            new_snap_id = clone_snapshot(session, old_snap_id)
        else:
            new_snap_id = clone_snapshot(session, old_snap_id, common.prepare_kms_key(session, kms_id))
        if new_snap_id == False:
            print("Snapshot encryption failed for snapshot {}".format(old_snap_id))
            return False
        
        # Step 3: Create new encrypted volume from cloned snapshot
        if 'Tags' in vol:
            new_vol_id = create_volume(session, new_snap_id, vol['AZ'], vol['VolumeType'], vol['Iops'], vol['Tags'])
        else:
            new_vol_id = create_volume(session, new_snap_id, vol['AZ'], vol['VolumeType'], vol['Iops'])
        
        if new_vol_id == False:
            print("Failed to create encrypted volume {}".format(new_vol_id))
            return False
        
        # Step 4: Attach encrypted volume to instance if applicable
        if vmid != "null":
            if not attach_to_vm(session, vol['VolumeId'], vmid, new_vol_id, vol['MountPath']):
                print("Failed to attach encrypted volume {} to instance {}".format(new_vol_id, vmid))
                return False
        
        # Step 5: Clean unwanted resources
        if not clean_resources(session, vol['VolumeId'], old_snap_id, new_snap_id):
            print("Failed to delete resources: {} {} {}".format(old_snap_id, new_snap_id, vol['VolumeId']))
            return False

        return True

def stop_instance(session, vm_id):
    try:
        ec2 = session.client('ec2')
        print("Stopping instance {}...".format(vm_id))
        ec2.stop_instances(
            InstanceIds=[
                vm_id
            ]
        )

        total_time = 0
        while True:
            resp = ec2.describe_instances(
                InstanceIds=[
                    vm_id
                ]
            )
            if resp['Reservations'][0]['Instances'][0]['State']['Name'] == 'stopped':
                print("Successfuly stopped instance {}".format(vm_id))
                return True
            
            time.sleep(5)
            total_time = total_time + 5
            print('Still stopping instance {}... {}s'.format(vm_id, total_time))
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False

def create_snapshot(session, vol_id):
    try:
        ec2 = session.client('ec2')
        print("Creating snapshot of volume {}...".format(vol_id))
        resp = ec2.create_snapshot(
            VolumeId=vol_id,
            Description='Unencrypted snapshot of {}'.format(vol_id)
        )
        snap_id = resp['SnapshotId']

        total_time = 0
        while True:
            resp = ec2.describe_snapshots(
                SnapshotIds=[
                    snap_id
                ]
            )
            if resp['Snapshots'][0]['State'] == 'completed':
                print("Successfully created snaphost {} of volume {}".format(snap_id, vol_id))
                return snap_id
            
            time.sleep(5)
            total_time = total_time + 5
            print('Still creating snapshot {}... {}s'.format(snap_id, total_time))
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False

def clone_snapshot(session, snap_id, kms_id="alias/aws/ebs"):
    try:
        ec2 = session.client('ec2')
        print("Encrypting snapshot {}...".format(snap_id))
        resp = ec2.copy_snapshot(
            SourceSnapshotId=snap_id,
            Description='Encryped snapshot of {}'.format(snap_id),
            Encrypted=True,
            KmsKeyId=kms_id,
            SourceRegion=session.region_name
        )
        new_snap_id = resp['SnapshotId']

        total_time = 0
        while True:
            resp = ec2.describe_snapshots(
                SnapshotIds=[
                    new_snap_id
                ]
            )
            if resp['Snapshots'][0]['State'] == 'completed':
                print("Successfully created encrypted snaphost {}".format(new_snap_id))
                return new_snap_id
            
            time.sleep(5)
            total_time = total_time + 5
            print('Still encrypting snapshot {}... {}s'.format(snap_id, total_time))
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False

def create_volume(session, new_snap_id, az, vol_type, iops, tags=None):
    try:
        ec2 = session.client('ec2')
        args = {
            'AvailabilityZone': az,
            'SnapshotId': new_snap_id,
            'VolumeType': vol_type
        }

        if tags != None:
            args['TagSpecifications'] = [
                {
                    'ResourceType': 'volume',
                    'Tags': tags
                }
            ]

        if vol_type == 'io1':
            args['Iops'] = iops

        print("Creating encrypted volume from snapshot {}...".format(new_snap_id))
        resp = ec2.create_volume(**args)
        new_vol_id = resp['VolumeId']

        total_time = 0
        while True:
            resp = ec2.describe_volumes(
                VolumeIds=[
                    new_vol_id
                ]
            )
            if resp['Volumes'][0]['State'] == 'available':
                print("Successfully created encrypted volume {} from snapshot {}...".format(new_vol_id, new_snap_id))
                return new_vol_id
            
            time.sleep(5)
            total_time = total_time + 5
            print('Still creating new volume {}... {}s'.format(new_vol_id, total_time))
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False

def attach_to_vm(session, old_vol_id, vm_id, new_vol_id, mount_path):
    try:
        ec2 = session.client('ec2')
        
        # Detach old volume
        print("Detaching old volume {} from instance {}...".format(old_vol_id, vm_id))
        ec2.detach_volume(
            VolumeId=old_vol_id,
            Force=True
        )

        total_time = 0
        while True:
            resp = ec2.describe_volumes(
                VolumeIds=[
                    old_vol_id
                ]
            )
            if resp['Volumes'][0]['State'] == 'available':
                print("Successfully detached old volume {} from instance {}".format(old_vol_id, vm_id))
                break
            
            time.sleep(5)
            total_time = total_time + 5
            print('Still detaching old volume {} from instance {}... {}s'.format(old_vol_id, vm_id, total_time))

        # Attach new volume
        print("Attching encrypted volume {} to instance {}...".format(new_vol_id, vm_id))
        ec2.attach_volume(
            InstanceId=vm_id,
            VolumeId=new_vol_id,
            Device=mount_path
        )

        total_time = 0
        while True:
            resp = ec2.describe_volumes(
                VolumeIds=[
                    new_vol_id
                ]
            )
            if resp['Volumes'][0]['State'] == 'in-use':
                print("Successfully attched encrypted volume {} to instance {}".format(new_vol_id, vm_id))
                return True
            
            time.sleep(5)
            total_time = total_time + 5
            print('Still attaching encrypted volume {} to instance {}... {}s'.format(new_vol_id, vm_id, total_time))
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False

def start_instance(session, vm_id):
    try:
        ec2 = session.client('ec2')
        print('Starting back instance {}...'.format(vm_id))
        ec2.start_instances(
            InstanceIds=[
                vm_id
            ]
        )

        total_time = 0
        while True:
            resp = ec2.describe_instances(
                InstanceIds=[
                    vm_id
                ]
            )
            if resp['Reservations'][0]['Instances'][0]['State']['Name'] == 'running':
                print('Successfully started instance {}'.format(vm_id))
                return True
            
            time.sleep(5)
            total_time = total_time + 5
            print('Still starting instance {}... {}s'.format(vm_id, total_time))
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False

def clean_resources(session, old_vol_id, old_snap_id, new_snap_id):
    try:
        ec2 = session.client('ec2')
        # Deleting old snapshot
        ec2.delete_snapshot(
            SnapshotId=old_snap_id
        )
        
        # Deleting new snapshot
        ec2.delete_snapshot(
            SnapshotId=new_snap_id
        )

        # Deleting old volume
        ec2.delete_volume(
            VolumeId=old_vol_id
        )

        return True
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False
