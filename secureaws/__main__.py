from secureaws import secureaws
import click

@click.command()
@click.option('--access-key', help='AWS IAM User Access Key')
@click.option('--secret-key', help='AWS IAM User Access Key')
@click.option('--profile', help='AWS CLI profile')
@click.option('--region', default='us-east-1', help='AWS region identifier. Default: us-east-1')
@click.option('--check', flag_value='check', help='Scan AWS account for basic security services')
def main(access_key, secret_key, profile, region, check):
    """
    This package will scan your AWS account to identify whether basic security services are enabled. If not, will help you enable the same.
    """
    secureaws_obj = secureaws(access_key, secret_key, profile, region)
    if not check:
        secureaws_obj.menu()
    else:
        secureaws_obj.check_account()
