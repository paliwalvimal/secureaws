import sys
from botocore.exceptions import ClientError

from secureaws import common

def check_account(session):
    """
    This will check if your account has basic security turned on or not.
    """

    try:
        sys.stdout.write("Checking CloudTrail... ")
        sys.stdout.flush()
        chk = check_cloudtrail(session)
        print("Enabled") if chk == True else print(chk)

        sys.stdout.write("Checking Config... ")
        sys.stdout.flush()
        chk = check_config(session)
        print("Enabled") if chk == True else print(chk)

        sys.stdout.write("Checking Flow Logs... ")
        sys.stdout.flush()
        chk = check_flowlogs(session)
        print("Enabled") if chk == True else print(chk)

        sys.stdout.write("Checking Root MFA... ")
        sys.stdout.flush()
        chk = check_root_mfa(session)
        print("Enabled") if chk == True else print(chk)

        sys.stdout.write("Checking Password Policy... ")
        sys.stdout.flush()
        chk = check_custom_password_policy(session)
        print("Passed") if chk == True else print(chk)

        sys.stdout.write("Checking Macie... ")
        sys.stdout.flush()
        chk = check_macie(session)
        print("Passed") if chk == True else print(chk)

        sys.stdout.write("Checking GuardDuty... ")
        sys.stdout.flush()
        chk = check_guard_duty(session)
        print("Passed") if chk == True else print(chk)

        print("=============================")
        print("Checking S3 Bucket Encryption")
        print("=============================")
        check_s3_buckets(session)

        print("==============================")
        print("Checking EC2 Volume Encryption")
        print("==============================")
        check_ec2_volumes(session)

        return True
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        return "Error: {}".format(ex)

def check_cloudtrail(session):
    """
    This will check if CloudTrail is enabled

    IAM Permission Required:
        - cloudtrail:DescribeTrails
    """
    
    try:
        cloudtrail = session.client('cloudtrail')
        resp = cloudtrail.describe_trails()
        if len(resp['trailList']) > 0:
            return True
        else:
            return "Disabled"
    except ClientError as e:
        return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
    except Exception as ex:
        return "Error: {}".format(ex)

def check_config(session):
    """
    This will check if Config is enabled

    IAM Permission Required:
        - config:DescribeConfigurationRecorderStatus
    """

    try:
        config = session.client('config')
        resp = config.describe_configuration_recorder_status()
        if len(resp['ConfigurationRecordersStatus']) > 0:
            return True
        else:
            return "Disabled"
    except ClientError as e:
        return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
    except Exception as ex:
        return "Error: {}".format(ex)

def check_flowlogs(session):
    """
    This will check if network flow logs are enabled

    IAM Permission Required:
        - ec2:DescribeFlowLogs
    """

    try:
        ec2 = session.client('ec2')
        resp = ec2.describe_flow_logs()
        if len(resp['FlowLogs']) > 0:
            return True
        else:
            return "Disabled"
    except ClientError as e:
        return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
    except Exception as ex:
        return "Error: {}".format(ex)

def check_root_mfa(session):
    """
    This will check if MFA for root account is enabled

    IAM Permission Required:
        - iam:GetAccountSummary
    """

    try:
        iam = session.client('iam')
        resp = iam.get_account_summary()
        if resp['SummaryMap']['AccountMFAEnabled'] == 1:
            return True
        else:
            return "Disabled"
    except ClientError as e:
        return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
    except Exception as ex:
        return "Error: {}".format(ex)

def check_custom_password_policy(session):
    """
    This will check if a strong password policy is set

    IAM Permission Required:
        - iam:GetAccountPasswordPolicy
    """

    try:
        iam = session.client('iam')
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

def check_s3_buckets(session):
    """
    This will check if server-side encryption is enabled for all your S3 buckets

    IAM Permission Required:
        - s3:ListAllMyBuckets
        - s3:GetEncryptionConfiguration
    """

    try:
        failed_buckets = []
        s3 = session.client('s3')
        resp = s3.list_buckets()
        for bucket in resp['Buckets']:
            bname = bucket['Name']
            try:
                sys.stdout.write("{}... ".format(bname))
                sys.stdout.flush()
                r = s3.get_bucket_encryption(Bucket=bname)
                print("Enabled")
            except ClientError as err:
                if err.response['Error']['Code'] == "ServerSideEncryptionConfigurationNotFoundError":
                    print("Disabled")
                    failed_buckets.append(bname)
                else:
                    print("Error: " + err.response['Error']['Code'] + " - " + err.response['Error']['Message'])
        
        if len(failed_buckets) > 0:
            return False
        else:
            return True
    except ClientError as e:
        return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
    except Exception as ex:
        return "Error: {}".format(ex)

def check_ec2_volumes(session):
    """
    This will check if server-side encryption is enabled for all your EBS volumes

    IAM Permission Required:
        - ec2:DescribeVolumes
    """

    try:
        failed_volumes = []
        ec2 = session.client('ec2')
        params = {}
        while True:
            resp = ec2.describe_volumes(**params)
            for volume in resp['Volumes']:
                vid = volume['VolumeId']
                vname = common.get_name_tag(volume['Tags']) if "Tags" in volume else None
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

def check_macie(session):
    """
    This will check if Macie is enabled

    IAM Permission Required:
        - macie:ListMemberAccounts
    """
    
    try:
        macie = session.client('macie')
        resp = macie.list_member_accounts()
        if len(resp['memberAccounts']) > 0:
            return True
    except ClientError as e:
        if "Macie is not enabled" in e.response['Error']['Message']:
            return "Disabled"
        return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
    except Exception as ex:
        if "Could not connect to the endpoint URL" in ex.args[0]:
            return "Service Unavailable"
        return "Error: {}".format(ex)

def check_guard_duty(session):
    """
    This will check if GuardDuty is enabled

    IAM Permission Required:
        - guardduty:ListDetectors
    """
    
    try:
        guardduty = session.client('guardduty')
        resp = guardduty.list_detectors()
        if len(resp['DetectorIds']) > 0:
            return True
        else:
            return "Disabled"

    except ClientError as e:
        return "Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message']
    except Exception as ex:
        return "Error: {}".format(ex)