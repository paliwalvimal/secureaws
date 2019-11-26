import secureaws
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
    awss3cure_obj = secureaws(access_key, secret_key, profile, region)
    if not check:
        awss3cure_obj.menu()
    else:
        awss3cure_obj.check_account()

if __name__ == '__main__':
    main()
