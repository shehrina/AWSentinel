# 🛡️ AWSentinel

An automated security scanning tool for AWS using Terraform and Python.

## 📌 Overview

This project automates security scanning for AWS cloud resources:
- Scans AWS resources for misconfigurations
- Stores findings in MongoDB
- Generates detailed security reports in JSON format

## ✨ Key Benefits

- **Automated Security**: Continuously monitors AWS resources for misconfigurations and vulnerabilities without manual intervention
- **Comprehensive Coverage**: Scans multiple AWS services including S3, EC2, IAM, and Security Groups
- **Actionable Insights**: Provides specific remediation steps for each security finding
- **Historical Tracking**: MongoDB integration allows for tracking security posture over time
- **Infrastructure as Code**: Terraform integration ensures security scanning infrastructure itself follows best practices
- **Extensible Design**: Modular architecture makes it easy to add support for new security checks or AWS services
- **Local Control**: All scanning happens from your environment, keeping sensitive security data under your control

## 🔧 Tech Stack & Tools

- **Python** - Custom security scanning scripts
- **Terraform** - Infrastructure as Code for setting up AWS resources
- **AWS** - Cloud security scanning
- **MongoDB** - Storage for scan findings

## ⚙️ Prerequisites

1. Python 3.8+
2. AWS CLI configured with appropriate credentials
3. Terraform installed
4. MongoDB server (local or remote)

## 🚀 Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd cloud-security-scanner
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your AWS credentials and MongoDB connection info
```

## 📁 Project Structure

```
cloud-security-scanner/
├── src/                       # Source code
│   ├── scanners/              # AWS security scanners
│   ├── remediators/           # Security issue remediators
│   ├── storage/               # MongoDB storage integration
│   └── terraform/             # Terraform automation
├── terraform/                 # Terraform modules
├── .env                       # Environment variables (not tracked by git)
├── .env.example               # Example environment variables
├── requirements.txt           # Python dependencies
└── run_scanner.py             # CLI to run the scanner
```

## 🔄 How It Works

1. **Cloud Scanning**
   - Scans AWS resources for security misconfigurations
   - Uses AWS SDK to analyze resource configurations
   - Applies security best practice checks

2. **Data Storage**
   - Stores findings in MongoDB for persistence
   - Maintains history of scans and findings

3. **Report Generation**
   - Generates JSON reports with timestamps
   - Provides detailed insights into security posture

## 🛠️ Usage

1. Start a security scan:
```bash
python -m src.main scan --cloud-provider AWS
```

2. Run with verbose output:
```bash
python -m src.main scan --cloud-provider AWS --verbose
```

3. Remediate a finding (using finding ID):
```bash
python -m src.main remediate <finding-id>
```

## 🔒 Security Best Practices

- Store sensitive credentials in environment variables
- Use IAM roles with minimum required permissions
- Enable MFA for all cloud accounts
- Regularly rotate API keys

# AWSentinel
