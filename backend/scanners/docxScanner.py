import os
import subprocess
import hashlib
import yara
from typing import Dict, List

class DOCXScanner:
    def __init__(self, rules_path: str):
        """Initialize YARA rules for DOCX scanning"""
        try:
            self.rules = yara.compile(filepath=rules_path)
        except Exception as e:
            raise Exception(f"Failed to compile YARA rules: {str(e)}")

    def scan_docx(self, file_path: str) -> Dict:
        """
        Scan a DOCX file using YARA rules.
        """
        try:
            matches = self.rules.match(file_path)
            
            threat_level = "low"
            max_weight = 0
            details = []
            
            for match in matches:
                weight = match.meta.get('weight', 0)
                max_weight = max(max_weight, weight)
                details.append({
                    "rule": match.rule,
                    "description": match.meta.get('description', 'No description available'),
                    "weight": weight
                })
            
            if max_weight >= 4:
                threat_level = "high"
            elif max_weight >= 2:
                threat_level = "medium"

            return {
                "status": "infected" if matches else "clean",
                "threat_level": threat_level,
                "yara_details": details if matches else "No threats found",
                "matches_count": len(matches)
            }
        except Exception as e:
            raise Exception(f"Error scanning file: {str(e)}")



    def generate_report(self, file_path: str) -> Dict:
        """
        Generate a simplified report for the DOCX file with detailed YARA scan results.
        """
        try:
            file_hash = self.calculate_hash(file_path)
            yara_results = self.scan_docx(file_path)

            return {
                "file_hash": file_hash,
                "threat_level": yara_results["threat_level"],
                "status": yara_results["status"],
                "yara_results": {
                    "matches_count": yara_results["matches_count"],
                    "details": yara_results["yara_details"]
                },
            }
        except Exception as e:
            raise Exception(f"Error generating simplified report: {str(e)}")
    
    def calculate_hash(self, file_path: str, algorithm='sha256') -> str:
        """
        Calculate the hash of a file.
        """
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
