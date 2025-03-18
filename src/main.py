import argparse
import json
from datetime import datetime
import logging

from src.config import settings
from src.scanners.aws_scanner import AWSScanner
from src.storage.mongodb_storage import MongoDBStorage
from src.remediators.aws_remediator import AWSRemediator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def scan_command(args):
    """Execute the scan command"""
    logger.info(f"Starting security scan for {args.cloud_provider}...")
    
    # Set log level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    try:
        # Initialize scanners based on provider
        if args.cloud_provider == 'AWS':
            scanner = AWSScanner(demo_mode=args.demo)
            findings = scanner.scan_resources() if not args.demo else []
                
        elif args.cloud_provider == 'ALL':
            aws_scanner = AWSScanner(demo_mode=args.demo)
            
            findings = []
            if not args.demo:
                findings.extend(aws_scanner.scan_resources())
        else:
            logger.error(f"Unsupported cloud provider: {args.cloud_provider}")
            return

        # Add summary of resources scanned
        if args.verbose:
            logger.debug(f"Scan completed. Found {len(findings)} issues.")
            if args.cloud_provider == 'AWS' or args.cloud_provider == 'ALL':
                aws_scanner = AWSScanner(demo_mode=args.demo)
                aws_scanner.print_resource_summary()

        # Store findings in MongoDB
        storage = MongoDBStorage()
        storage.store_findings(findings)
        
        # Generate report
        report = {
            "scan_id": f"scan-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "cloud_provider": args.cloud_provider,
            "findings_count": len(findings),
            "findings": findings
        }
        
        # Save report to file
        report_file = f"security_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Scan completed. Report saved to {report_file}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

def remediate_command(args):
    """Execute the remediate command"""
    logger.info(f"Starting remediation for {args.finding_id}...")
    
    try:
        # Get finding from storage
        storage = MongoDBStorage()
        finding = storage.get_finding(args.finding_id)
        
        if not finding:
            logger.error(f"Finding with ID {args.finding_id} not found")
            return
            
        # Initialize remediator based on provider
        cloud_provider = finding.get('provider', 'UNKNOWN')
        if cloud_provider == 'AWS':
            remediator = AWSRemediator(demo_mode=True)  # Always use demo mode for remediation
        else:
            logger.error(f"Unsupported cloud provider for remediation: {cloud_provider}")
            return
            
        # Execute remediation
        success = remediator.remediate_finding(finding)
        
        if success:
            # Update finding status
            storage.update_finding_status(args.finding_id, 'REMEDIATED')
            logger.info(f"Successfully remediated finding {args.finding_id}")
        else:
            logger.error(f"Failed to remediate finding {args.finding_id}")
            
    except Exception as e:
        logger.error(f"Error: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='AWS security scanner and compliance enforcer')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan cloud resources for security issues')
    scan_parser.add_argument('--cloud-provider', choices=['AWS', 'ALL'], default='AWS',
                            help='Cloud provider to scan')
    scan_parser.add_argument('--demo', action='store_true', help='Run in demo mode with mock data')
    scan_parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    # Remediate command
    remediate_parser = subparsers.add_parser('remediate', help='Remediate a security finding')
    remediate_parser.add_argument('finding_id', help='ID of the finding to remediate')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        scan_command(args)
    elif args.command == 'remediate':
        remediate_command(args)
    else:
        parser.print_help()
        
if __name__ == '__main__':
    main() 