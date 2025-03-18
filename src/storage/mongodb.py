from typing import Dict, List, Optional
from datetime import datetime
from pymongo import MongoClient
from pymongo.collection import Collection
from src.config import settings

class MongoDBStorage:
    def __init__(self):
        self.client = MongoClient(settings.mongodb_uri)
        self.db = self.client[settings.mongodb_db_name]
        
        # Collections
        self.scan_results = self.db.scan_results
        self.compliance_reports = self.db.compliance_reports
        self.remediation_history = self.db.remediation_history
        
        # Create indexes
        self._setup_indexes()

    def _setup_indexes(self):
        """
        Set up MongoDB indexes for better query performance
        """
        # Scan results indexes
        self.scan_results.create_index([("timestamp", -1)])
        self.scan_results.create_index([("cloud_provider", 1)])
        self.scan_results.create_index([("severity", 1)])

        # Compliance reports indexes
        self.compliance_reports.create_index([("timestamp", -1)])
        self.compliance_reports.create_index([("framework_name", 1)])

        # Remediation history indexes
        self.remediation_history.create_index([("timestamp", -1)])
        self.remediation_history.create_index([("resource_id", 1)])

    def store_scan_results(self, results: Dict) -> str:
        """
        Store security scan results
        """
        document = {
            "timestamp": datetime.now(),
            "results": results
        }
        result = self.scan_results.insert_one(document)
        return str(result.inserted_id)

    def store_compliance_report(self, report: Dict) -> str:
        """
        Store compliance report
        """
        document = {
            "timestamp": datetime.now(),
            "report": report
        }
        result = self.compliance_reports.insert_one(document)
        return str(result.inserted_id)

    def store_remediation_action(self, action: Dict) -> str:
        """
        Store remediation action history
        """
        document = {
            "timestamp": datetime.now(),
            "action": action
        }
        result = self.remediation_history.insert_one(document)
        return str(result.inserted_id)

    def get_latest_scan_results(self, limit: int = 10) -> List[Dict]:
        """
        Get the most recent scan results
        """
        return list(self.scan_results.find()
                   .sort("timestamp", -1)
                   .limit(limit))

    def get_scan_results_by_severity(self, severity: str) -> List[Dict]:
        """
        Get scan results filtered by severity
        """
        return list(self.scan_results.find({"results.severity": severity}))

    def get_compliance_history(self, framework_name: Optional[str] = None) -> List[Dict]:
        """
        Get compliance report history
        """
        query = {"report.framework_name": framework_name} if framework_name else {}
        return list(self.compliance_reports.find(query).sort("timestamp", -1))

    def get_remediation_history(self, resource_id: Optional[str] = None) -> List[Dict]:
        """
        Get remediation action history
        """
        query = {"action.resource_id": resource_id} if resource_id else {}
        return list(self.remediation_history.find(query).sort("timestamp", -1))

    def generate_summary_report(self) -> Dict:
        """
        Generate a summary report of all stored data
        """
        latest_scan = self.get_latest_scan_results(1)
        latest_compliance = list(self.compliance_reports.find()
                               .sort("timestamp", -1)
                               .limit(1))
        
        return {
            "timestamp": datetime.now(),
            "latest_scan": latest_scan[0] if latest_scan else None,
            "latest_compliance": latest_compliance[0] if latest_compliance else None,
            "total_scans": self.scan_results.count_documents({}),
            "total_remediations": self.remediation_history.count_documents({})
        }

    def cleanup_old_data(self, days_to_keep: int = 30):
        """
        Clean up data older than specified days
        """
        cutoff_date = datetime.now() - datetime.timedelta(days=days_to_keep)
        
        self.scan_results.delete_many({"timestamp": {"$lt": cutoff_date}})
        self.compliance_reports.delete_many({"timestamp": {"$lt": cutoff_date}})
        self.remediation_history.delete_many({"timestamp": {"$lt": cutoff_date}}) 