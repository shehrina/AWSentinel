import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from typing import Dict, List, Optional
from src.config import settings
import json

class AlertManager:
    def __init__(self):
        self.slack_webhook_url = settings.slack_webhook_url
        self.smtp_host = settings.smtp_host
        self.smtp_port = settings.smtp_port
        self.smtp_username = settings.smtp_username
        self.smtp_password = settings.smtp_password

    def send_slack_alert(self, message: str, severity: str = "info") -> bool:
        """
        Send alert to Slack
        """
        if not self.slack_webhook_url:
            return False

        color_map = {
            "critical": "#FF0000",
            "high": "#FFA500",
            "medium": "#FFFF00",
            "low": "#00FF00",
            "info": "#0000FF"
        }

        payload = {
            "attachments": [{
                "color": color_map.get(severity.lower(), "#0000FF"),
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message
                        }
                    }
                ]
            }]
        }

        try:
            response = requests.post(
                self.slack_webhook_url,
                json=payload
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Failed to send Slack alert: {str(e)}")
            return False

    def send_email_alert(self, subject: str, body: str, recipients: List[str]) -> bool:
        """
        Send alert via email
        """
        if not all([self.smtp_username, self.smtp_password]):
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
            server.quit()
            return True
        except Exception as e:
            print(f"Failed to send email alert: {str(e)}")
            return False

    def format_security_alert(self, issue: Dict) -> Dict[str, str]:
        """
        Format security issue for alerts
        """
        severity = issue.get("severity", "unknown").upper()
        resource = issue.get("resource", {})
        
        slack_message = f"""
*Security Issue Detected*
Severity: {severity}
Title: {issue.get('title')}
Resource: {resource.get('name')} ({resource.get('type')})
Region: {resource.get('region')}
Description: {issue.get('description')}
"""

        email_body = f"""
Security Issue Detected

Severity: {severity}
Title: {issue.get('title')}
Resource: {resource.get('name')} ({resource.get('type')})
Region: {resource.get('region')}

Description:
{issue.get('description')}

Please take immediate action if required.
"""

        return {
            "slack_message": slack_message.strip(),
            "email_subject": f"[{severity}] Security Issue Detected - {issue.get('title')}",
            "email_body": email_body.strip()
        }

    def format_compliance_alert(self, compliance_data: Dict) -> Dict[str, str]:
        """
        Format compliance report for alerts
        """
        failed_controls = compliance_data.get("failed_controls", [])
        total_controls = compliance_data.get("total_controls", 0)
        
        slack_message = f"""
*Compliance Status Update*
Framework: {compliance_data.get('framework')}
Status: {len(failed_controls)}/{total_controls} controls failed

Failed Controls:
{chr(10).join(f"• {control}" for control in failed_controls[:5])}
"""

        email_body = f"""
Compliance Status Update

Framework: {compliance_data.get('framework')}
Status: {len(failed_controls)}/{total_controls} controls failed

Failed Controls:
{chr(10).join(f"- {control}" for control in failed_controls)}

Please review and address these compliance issues.
"""

        return {
            "slack_message": slack_message.strip(),
            "email_subject": f"Compliance Status Update - {compliance_data.get('framework')}",
            "email_body": email_body.strip()
        }

    def send_security_alert(self, issue: Dict, recipients: List[str]) -> Dict[str, bool]:
        """
        Send security alert through all configured channels
        """
        formatted_alert = self.format_security_alert(issue)
        
        results = {
            "slack": self.send_slack_alert(
                formatted_alert["slack_message"],
                issue.get("severity", "info")
            ),
            "email": self.send_email_alert(
                formatted_alert["email_subject"],
                formatted_alert["email_body"],
                recipients
            )
        }
        
        return results

    def send_compliance_alert(self, compliance_data: Dict, recipients: List[str]) -> Dict[str, bool]:
        """
        Send compliance alert through all configured channels
        """
        formatted_alert = self.format_compliance_alert(compliance_data)
        
        results = {
            "slack": self.send_slack_alert(
                formatted_alert["slack_message"],
                "high" if compliance_data.get("failed_controls") else "info"
            ),
            "email": self.send_email_alert(
                formatted_alert["email_subject"],
                formatted_alert["email_body"],
                recipients
            )
        }
        
        return results 