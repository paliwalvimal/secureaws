import secrets
from botocore.exceptions import ClientError

def check_bucket_exists(session, bname):
    """
    IAM Permission Required:
        - s3:HeadBucket
    """
    s3 = session.client('s3')
    try:
        r = s3.head_bucket(Bucket=bname)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == "403":
            return True
        else:
            return False

def create_s3_bucket(session, bname, region):
    """
    IAM Permission Required:
        - s3:CreateBucket
    """
    try:
        s3 = session.client('s3')
        req = {
            "Bucket": bname,
            "ACL": "private"
        }

        if region != "us-east-1":
            tmpObj = {
                "LocationConstraint": region
            }
            req["CreateBucketConfiguration"] = tmpObj

        s3.create_bucket(**req)
        return True
    except ClientError as e:
        return "Error: {}-{}".format(e.response['Error']['Code'], e.response['Error']['Message'])
    except Exception as ex:
        return "Error: {}".format(ex)

def get_account_id(session):
    """
    IAM Permission Required:
        - sts:GetCallerIdentity
    """
    sts = session.client('sts')
    return sts.get_caller_identity()['Account']

def get_name_tag(tags):
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    
    return None

def random_string(len):
    return secrets.token_hex()[0:len]

def prepare_kms_key(session, kms_id):
    if 'arn:' in kms_id:
        return kms_id
    elif 'alias/' in kms_id:
        return 'arn:aws:kms:{}:{}:{}'.format(session.region_name, get_account_id(session), kms_id)
    else:
        return 'arn:aws:kms:{}:{}:key/{}'.format(session.region_name, get_account_id(session), kms_id)