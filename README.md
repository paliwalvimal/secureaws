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

## Installation (Any 1)
- pip3 install secureaws
- Clone the repo and run `python3 setup.py install`

## Usage (Any 1)
- secureaws --access-key XXXXXX --secret-key XXXXXX --region us-east-1
- secureaws --profile XXXXXX --region us-east-1
- secureaws --region us-east-1
- secureaws --help
