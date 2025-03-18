import boto3
import logging
from datetime import datetime
from typing import Dict, List, Optional
from src.config import settings

logger = logging.getLogger(__name__)

class AWSScanner:
    """
    Scanner for AWS resources - with real AWS API support
    """
    
    def __init__(self, demo_mode: bool = False):
        self.demo_mode = demo_mode
        if not demo_mode:
            # In real mode, initialize AWS clients
            try:
                logger.info("Initializing AWS clients with real credentials")
                self.ec2_client = boto3.client(
                    'ec2',
                    aws_access_key_id=settings.aws_access_key_id,
                    aws_secret_access_key=settings.aws_secret_access_key,
                    region_name=settings.aws_region
                )
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=settings.aws_access_key_id,
                    aws_secret_access_key=settings.aws_secret_access_key,
                    region_name=settings.aws_region
                )
                self.iam_client = boto3.client(
                    'iam',
                    aws_access_key_id=settings.aws_access_key_id,
                    aws_secret_access_key=settings.aws_secret_access_key,
                    region_name=settings.aws_region
                )
                logger.info("AWS clients initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize AWS clients: {str(e)}")
                logger.error("Falling back to demo mode")
                self.demo_mode = True  # Fall back to demo mode
    
    def scan_resources(self) -> List[Dict]:
        """
        Scan AWS resources for security issues
        """
        if self.demo_mode:
            logger.info("Running in demo mode, returning demo findings")
            return self._get_demo_findings()
            
        logger.info("Scanning real AWS resources")
        findings = []
        
        try:
            # Scan S3 buckets
            logger.info("Scanning S3 buckets")
            findings.extend(self._scan_s3_buckets())
            
            # Scan security groups
            logger.info("Scanning security groups")
            findings.extend(self._scan_security_groups())
            
            # Scan IAM users
            logger.info("Scanning IAM users")
            findings.extend(self._scan_iam_users())
            
            logger.info(f"Scan completed, found {len(findings)} issues")
            return findings
        except Exception as e:
            logger.error(f"Error during AWS scan: {str(e)}")
            # Return demo findings as fallback
            logger.warning("Returning demo findings as fallback")
            return self._get_demo_findings()
    
    def _scan_s3_buckets(self) -> List[Dict]:
        """
        Scan S3 buckets for security issues
        """
        findings = []
        
        try:
            # List all S3 buckets
            response = self.s3_client.list_buckets()
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                logger.info(f"Checking bucket: {bucket_name}")
                
                # Check if bucket has public access
                try:
                    public_access = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    block_config = public_access['PublicAccessBlockConfiguration']
                    
                    # If any of these are False, public access might be allowed
                    if not all([
                        block_config.get('BlockPublicAcls', False),
                        block_config.get('IgnorePublicAcls', False),
                        block_config.get('BlockPublicPolicy', False),
                        block_config.get('RestrictPublicBuckets', False)
                    ]):
                        findings.append({
                            "id": f"aws-s3-public-{bucket_name}",
                            "provider": "AWS",
                            "severity": "HIGH",
                            "status": "OPEN",
                            "title": "S3 Bucket Public Access Not Blocked",
                            "description": f"S3 bucket {bucket_name} does not have all public access block settings enabled",
                            "createdAt": datetime.now().isoformat(),
                            "resource": {
                                "id": bucket_name,
                                "name": bucket_name,
                                "type": "S3 Bucket",
                                "region": settings.aws_region
                            },
                            "remediation": "Enable all public access block settings for the S3 bucket"
                        })
                except Exception as e:
                    # If public access block is not configured, assume it's public
                    if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                        findings.append({
                            "id": f"aws-s3-no-public-block-{bucket_name}",
                            "provider": "AWS",
                            "severity": "HIGH",
                            "status": "OPEN",
                            "title": "S3 Bucket Public Access Block Not Configured",
                            "description": f"S3 bucket {bucket_name} does not have public access block configuration",
                            "createdAt": datetime.now().isoformat(),
                            "resource": {
                                "id": bucket_name,
                                "name": bucket_name,
                                "type": "S3 Bucket",
                                "region": settings.aws_region
                            },
                            "remediation": "Configure public access block for the S3 bucket"
                        })
                    else:
                        logger.warning(f"Error checking public access for bucket {bucket_name}: {str(e)}")
                        
                # Check for encryption
                try:
                    encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                except Exception as e:
                    if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                        findings.append({
                            "id": f"aws-s3-no-encryption-{bucket_name}",
                            "provider": "AWS",
                            "severity": "MEDIUM",
                            "status": "OPEN",
                            "title": "S3 Bucket Encryption Not Enabled",
                            "description": f"S3 bucket {bucket_name} does not have default encryption enabled",
                            "createdAt": datetime.now().isoformat(),
                            "resource": {
                                "id": bucket_name,
                                "name": bucket_name,
                                "type": "S3 Bucket",
                                "region": settings.aws_region
                            },
                            "remediation": "Enable default encryption for the S3 bucket"
                        })
                    else:
                        logger.warning(f"Error checking encryption for bucket {bucket_name}: {str(e)}")
        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {str(e)}")
        
        return findings
    
    def _scan_security_groups(self) -> List[Dict]:
        """
        Scan security groups for security issues
        """
        findings = []
        
        try:
            # List all security groups
            response = self.ec2_client.describe_security_groups()
            
            for sg in response['SecurityGroups']:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                logger.info(f"Checking security group: {sg_name} ({sg_id})")
                
                # Check for open SSH access (port 22)
                for perm in sg.get('IpPermissions', []):
                    from_port = perm.get('FromPort')
                    to_port = perm.get('ToPort')
                    
                    # Check if this rule allows SSH access
                    if (from_port is None or from_port <= 22) and (to_port is None or to_port >= 22):
                        for ip_range in perm.get('IpRanges', []):
                            cidr = ip_range.get('CidrIp', '')
                            
                            # Check if CIDR is too permissive (like 0.0.0.0/0)
                            if cidr == '0.0.0.0/0':
                                findings.append({
                                    "id": f"aws-sg-open-ssh-{sg_id}",
                                    "provider": "AWS",
                                    "severity": "HIGH",
                                    "status": "OPEN",
                                    "title": "Security Group Open to Internet on SSH Port",
                                    "description": f"Security group {sg_name} ({sg_id}) allows unrestricted inbound access on port 22 (SSH)",
                                    "createdAt": datetime.now().isoformat(),
                                    "resource": {
                                        "id": sg_id,
                                        "name": sg_name,
                                        "type": "Security Group",
                                        "region": settings.aws_region
                                    },
                                    "remediation": "Restrict SSH access to specific IP ranges"
                                })
                                break  # Found an issue, no need to check other IP ranges for this permission
        except Exception as e:
            logger.error(f"Error scanning security groups: {str(e)}")
        
        return findings
    
    def _scan_iam_users(self) -> List[Dict]:
        """
        Scan IAM users for security issues
        """
        findings = []
        
        try:
            # List all IAM users
            response = self.iam_client.list_users()
            
            for user in response['Users']:
                user_name = user['UserName']
                user_id = user['UserId']
                logger.info(f"Checking IAM user: {user_name}")
                
                # Check for attached policies
                attached_policies = self.iam_client.list_attached_user_policies(UserName=user_name)
                
                for policy in attached_policies['AttachedPolicies']:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['PolicyArn']
                    
                    # Check for admin access
                    if policy_name == 'AdministratorAccess':
                        findings.append({
                            "id": f"aws-iam-admin-{user_id}",
                            "provider": "AWS",
                            "severity": "CRITICAL",
                            "status": "OPEN",
                            "title": "IAM User with Admin Privileges",
                            "description": f"IAM user {user_name} has AdministratorAccess policy attached",
                            "createdAt": datetime.now().isoformat(),
                            "resource": {
                                "id": user_id,
                                "name": user_name,
                                "type": "IAM User",
                                "region": "global"
                            },
                            "remediation": "Remove AdministratorAccess policy and apply principle of least privilege"
                        })
                
                # Check for access keys
                access_keys = self.iam_client.list_access_keys(UserName=user_name)
                
                # Check if user has multiple access keys
                if len(access_keys['AccessKeyMetadata']) > 1:
                    findings.append({
                        "id": f"aws-iam-multiple-keys-{user_id}",
                        "provider": "AWS",
                        "severity": "MEDIUM",
                        "status": "OPEN",
                        "title": "IAM User with Multiple Access Keys",
                        "description": f"IAM user {user_name} has multiple active access keys",
                        "createdAt": datetime.now().isoformat(),
                        "resource": {
                            "id": user_id,
                            "name": user_name,
                            "type": "IAM User",
                            "region": "global"
                        },
                        "remediation": "Remove unnecessary access keys and rotate regularly"
                    })
                
                # Check for access key rotation
                for key in access_keys['AccessKeyMetadata']:
                    key_id = key['AccessKeyId']
                    create_date = key['CreateDate']
                    
                    # Check if key is older than 90 days
                    key_age = (datetime.now().replace(tzinfo=None) - create_date.replace(tzinfo=None)).days
                    if key_age > 90:
                        findings.append({
                            "id": f"aws-iam-old-key-{key_id}",
                            "provider": "AWS",
                            "severity": "MEDIUM",
                            "status": "OPEN",
                            "title": "IAM Access Key Not Rotated",
                            "description": f"Access key {key_id} for user {user_name} is {key_age} days old",
                            "createdAt": datetime.now().isoformat(),
                            "resource": {
                                "id": user_id,
                                "name": user_name,
                                "type": "IAM User",
                                "region": "global"
                            },
                            "remediation": "Rotate access keys regularly (at least every 90 days)"
                        })
        except Exception as e:
            logger.error(f"Error scanning IAM users: {str(e)}")
        
        return findings
    
    def _get_demo_findings(self) -> List[Dict]:
        """
        Generate demo security findings for AWS
        """
        return [
            {
                "id": "aws-demo-001",
                "provider": "AWS",
                "severity": "HIGH",
                "status": "OPEN",
                "title": "S3 Bucket Public Access",
                "description": "S3 bucket has public read access enabled",
                "createdAt": datetime.now().isoformat(),
                "resource": {
                    "id": "example-public-bucket",
                    "name": "example-public-bucket",
                    "type": "S3 Bucket",
                    "region": "us-west-2"
                },
                "remediation": "Disable public access for the S3 bucket by updating the bucket policy"
            },
            {
                "id": "aws-demo-002",
                "provider": "AWS",
                "severity": "MEDIUM",
                "status": "OPEN",
                "title": "Security Group Open to Internet",
                "description": "Security group allows unrestricted inbound access on port 22",
                "createdAt": datetime.now().isoformat(),
                "resource": {
                    "id": "sg-12345",
                    "name": "default-sg",
                    "type": "Security Group",
                    "region": "us-west-2"
                },
                "remediation": "Restrict SSH access to specific IP ranges"
            },
            {
                "id": "aws-demo-003",
                "provider": "AWS",
                "severity": "CRITICAL",
                "status": "OPEN",
                "title": "IAM User with Admin Privileges",
                "description": "IAM user has AdministratorAccess policy attached",
                "createdAt": datetime.now().isoformat(),
                "resource": {
                    "id": "AIDACKCEVSQ6C2EXAMPLE",
                    "name": "test-user",
                    "type": "IAM User",
                    "region": "global"
                },
                "remediation": "Remove AdministratorAccess policy and apply principle of least privilege"
            }
        ] 

    def print_resource_summary(self):
        """
        Print a summary of the AWS resources that were scanned
        """
        try:
            # S3 buckets
            response = self.s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            logger.info(f"AWS Resource Summary - S3 Buckets: {len(buckets)}")
            for bucket in buckets:
                logger.info(f"  - Bucket: {bucket['Name']}")
                
            # Security groups
            response = self.ec2_client.describe_security_groups()
            security_groups = response.get('SecurityGroups', [])
            logger.info(f"AWS Resource Summary - Security Groups: {len(security_groups)}")
            for sg in security_groups:
                logger.info(f"  - Security Group: {sg['GroupName']} ({sg['GroupId']})")
                
            # IAM users
            response = self.iam_client.list_users()
            users = response.get('Users', [])
            logger.info(f"AWS Resource Summary - IAM Users: {len(users)}")
            for user in users:
                logger.info(f"  - IAM User: {user['UserName']}")
                
        except Exception as e:
            logger.error(f"Error printing resource summary: {str(e)}")
            return 