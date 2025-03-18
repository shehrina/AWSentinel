import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

import pymongo
from pymongo.collection import Collection
from pymongo.database import Database

from src.config import settings

logger = logging.getLogger(__name__)

class MongoDBStorage:
    """
    MongoDB storage class for security findings
    """
    
    def __init__(self):
        try:
            self.client = pymongo.MongoClient(settings.mongodb_uri)
            self.db = self.client[settings.mongodb_db_name]
            self.findings_collection = self.db.findings
            self.reports_collection = self.db.reports
            
            # Create indexes for faster queries
            self.findings_collection.create_index([("id", pymongo.ASCENDING)], unique=True)
            self.findings_collection.create_index([("provider", pymongo.ASCENDING)])
            self.findings_collection.create_index([("severity", pymongo.ASCENDING)])
            self.findings_collection.create_index([("status", pymongo.ASCENDING)])
            self.findings_collection.create_index([("createdAt", pymongo.DESCENDING)])
            
            logger.info("Connected to MongoDB successfully")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            # Create a fallback in-memory storage
            self.findings_in_memory = []
            self.reports_in_memory = []
    
    def store_findings(self, findings: List[Dict]) -> int:
        """
        Store security findings in MongoDB
        Returns the number of findings stored
        """
        if not hasattr(self, 'findings_collection'):
            # Fallback to in-memory storage
            for finding in findings:
                if finding not in self.findings_in_memory:
                    self.findings_in_memory.append(finding)
            return len(findings)
        
        stored_count = 0
        for finding in findings:
            # Add timestamp if not present
            if 'timestamp' not in finding:
                finding['timestamp'] = datetime.now().isoformat()
                
            try:
                # Use upsert to avoid duplicates
                result = self.findings_collection.update_one(
                    {"id": finding["id"]},
                    {"$set": finding},
                    upsert=True
                )
                
                if result.upserted_id is not None or result.modified_count > 0:
                    stored_count += 1
            except Exception as e:
                logger.error(f"Failed to store finding {finding.get('id')}: {str(e)}")
        
        return stored_count
    
    def get_finding(self, finding_id: str) -> Optional[Dict]:
        """
        Get a specific finding by ID
        """
        if not hasattr(self, 'findings_collection'):
            # Fallback to in-memory storage
            for finding in self.findings_in_memory:
                if finding.get('id') == finding_id:
                    return finding
            return None
        
        try:
            finding = self.findings_collection.find_one({"id": finding_id})
            return finding
        except Exception as e:
            logger.error(f"Failed to get finding {finding_id}: {str(e)}")
            return None
    
    def get_findings(self, query: Dict = None, limit: int = 100) -> List[Dict]:
        """
        Get findings based on query
        """
        if not hasattr(self, 'findings_collection'):
            # Fallback to in-memory storage
            if query is None:
                return self.findings_in_memory[:limit]
            
            # Simple filtering implementation for in-memory fallback
            results = []
            for finding in self.findings_in_memory:
                match = True
                for key, value in query.items():
                    if key not in finding or finding[key] != value:
                        match = False
                        break
                if match:
                    results.append(finding)
                    if len(results) >= limit:
                        break
            return results
        
        try:
            cursor = self.findings_collection.find(query or {}).sort("createdAt", -1).limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Failed to get findings: {str(e)}")
            return []
    
    def update_finding_status(self, finding_id: str, status: str) -> bool:
        """
        Update the status of a finding
        """
        if not hasattr(self, 'findings_collection'):
            # Fallback to in-memory storage
            for finding in self.findings_in_memory:
                if finding.get('id') == finding_id:
                    finding['status'] = status
                    return True
            return False
        
        try:
            result = self.findings_collection.update_one(
                {"id": finding_id},
                {"$set": {"status": status, "updatedAt": datetime.now().isoformat()}}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update finding status {finding_id}: {str(e)}")
            return False
    
    def store_report(self, report: Dict) -> str:
        """
        Store a security report
        Returns the report ID
        """
        if not hasattr(self, 'reports_collection'):
            # Fallback to in-memory storage
            report_id = f"report-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            report['id'] = report_id
            self.reports_in_memory.append(report)
            return report_id
        
        try:
            # Ensure the report has an ID
            if 'id' not in report:
                report['id'] = f"report-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                
            # Add timestamp if not present
            if 'timestamp' not in report:
                report['timestamp'] = datetime.now().isoformat()
                
            self.reports_collection.insert_one(report)
            return report['id']
        except Exception as e:
            logger.error(f"Failed to store report: {str(e)}")
            return None 