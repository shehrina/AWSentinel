#!/usr/bin/env python
import sys
import os
import subprocess
import logging
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_scanner():
    """Run the AWS security scanner with appropriate arguments."""
    
    # Make sure we're in a virtual environment
    if not sys.prefix != sys.base_prefix:
        logger.warning("Not running in a virtual environment. Continuing anyway.")
    
    # Check if .env file exists
    env_file = Path(".env")
    if not env_file.exists():
        logger.error("Error: .env file not found. Please create one with your AWS credentials.")
        return 1
    
    logger.info(f"Starting security scan on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("Using credentials from .env file")
    
    # Run the scanner
    try:
        # Run the scanner with the correct arguments
        result = subprocess.run([sys.executable, "-m", "src.main", "scan", "--cloud-provider", "AWS", "--verbose"],
                             capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"Error running scanner: {result.stderr}")
            return result.returncode
        
        logger.info(result.stdout)
        
        # Find the latest report file
        report_files = list(Path(".").glob("security_report_*.json"))
        if report_files:
            latest_report = max(report_files, key=lambda x: x.stat().st_mtime)
            logger.info(f"Latest scan report saved as {latest_report}")
            
            # Preview the report
            with open(latest_report, "r") as f:
                content = f.read()
                logger.info(f"Report preview: {content[:300]}...")
        else:
            logger.warning("No report files found after scan")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return 1
    
if __name__ == "__main__":
    sys.exit(run_scanner()) 