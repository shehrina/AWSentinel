import logging
from typing import Dict, List, Optional
import boto3

from src.config import settings

logger = logging.getLogger(__name__)

class AWSRemediator:
    """
    Remediator for AWS security findings - demo implementation
    """
    
    def __init__(self, demo_mode: bool = True):
        self.demo_mode = demo_mode
        if not demo_mode:
            try:
                # Initialize AWS clients
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
            except Exception as e:
                logger.error(f"Failed to initialize AWS clients: {str(e)}")
                self.demo_mode = True  # Fall back to demo mode
    
    def remediate_finding(self, finding: Dict) -> bool:
        """
        Remediate a security finding
        """
        if self.demo_mode:
            # In demo mode, we simulate remediation
            finding_id = finding.get('id', 'unknown')
            resource_type = finding.get('resource', {}).get('type', '').lower()
            
            logger.info(f"[DEMO] Remediating finding {finding_id}")
            
            if 's3' in resource_type or 'bucket' in resource_type:
                return self._demo_remediate_s3_bucket(finding)
            elif 'security group' in resource_type or 'sg' in resource_type:
                return self._demo_remediate_security_group(finding)
            elif 'iam' in resource_type or 'user' in resource_type:
                return self._demo_remediate_iam_user(finding)
            else:
                logger.warning(f"[DEMO] No remediation available for resource type: {resource_type}")
                return False
        
        # In real mode, we would actually make AWS API calls to remediate the issue
        resource_type = finding.get('resource', {}).get('type', '').lower()
        resource_id = finding.get('resource', {}).get('id', '')
        
        if 's3' in resource_type or 'bucket' in resource_type:
            bucket_name = resource_id
            try:
                # Example: Make bucket private
                self.s3_client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                logger.info(f"Remediated public access for S3 bucket: {bucket_name}")
                return True
            except Exception as e:
                logger.error(f"Failed to remediate S3 bucket {bucket_name}: {str(e)}")
                return False
                
        elif 'security group' in resource_type:
            sg_id = resource_id
            try:
                # Example: Remove wide open SSH rule
                self.ec2_client.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }
                    ]
                )
                logger.info(f"Remediated security group {sg_id} by removing public SSH access")
                return True
            except Exception as e:
                logger.error(f"Failed to remediate security group {sg_id}: {str(e)}")
                return False
                
        else:
            logger.warning(f"No remediation available for resource type: {resource_type}")
            return False
    
    def _demo_remediate_s3_bucket(self, finding: Dict) -> bool:
        """
        Simulate remediation for S3 bucket findings
        """
        resource_name = finding.get('resource', {}).get('name', 'unknown-bucket')
        logger.info(f"[DEMO] Remediated S3 bucket {resource_name} - Made bucket private")
        return True
        
    def _demo_remediate_security_group(self, finding: Dict) -> bool:
        """
        Simulate remediation for security group findings
        """
        resource_name = finding.get('resource', {}).get('name', 'unknown-sg')
        logger.info(f"[DEMO] Remediated security group {resource_name} - Removed public SSH access")
        return True
        
    def _demo_remediate_iam_user(self, finding: Dict) -> bool:
        """
        Simulate remediation for IAM user findings
        """
        resource_name = finding.get('resource', {}).get('name', 'unknown-user')
        logger.info(f"[DEMO] Remediated IAM user {resource_name} - Removed admin permissions and applied least privilege")
        return True 