# secure-aws

This package will scan your AWS account to identify whether basic security services are enabled. If not, will help you enable/setup the same.

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
