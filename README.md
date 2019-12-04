# secure-aws

This package will scan your AWS account to identify whether basic security services are enabled. If not, will help you enable the same.

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

## Usage:
- To display menu: `secureaws menu`
- Scan AWS account using AWS keys: `secureaws check --access-key XXXXXX --secret-key XXXXXX --region us-west-2`
- Scan AWS account using profile: `secureaws check --profile xxx --region eu-west-1`
- Setup all services: `secureaws setup --profile XXXXXX --region ap-south-1`
- Setup specific service(s): `secureaws setup --profile XXXXXX --region ap-south-1 -s config -s mfa`
- Setup all services in non-interactive mode: `secureaws setup --access-key XXXXXX --secret-key XXXXXX -y`
- Generate RSA Key Pair: `secureaws genrsa`
