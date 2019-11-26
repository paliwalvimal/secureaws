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

## Installation
- pip install secureaws
- Clone the repo and run `setup.py install`

## Usage
- secureaws --access-key XXXXXX --secret-key XXXXXX --region us-east-1
- secureaws --profile XXXXXX --region us-east-1
- secureaws --region us-east-1
- secureaws --help
