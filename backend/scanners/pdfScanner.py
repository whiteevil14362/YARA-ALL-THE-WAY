import yara
from typing import Dict

class PDFScanner:
    def __init__(self, rules_path: str):
        """Initialize YARA rules for PDF scanning"""
        try:
            self.rules = yara.compile(filepath=rules_path)
        except Exception as e:
            raise Exception(f"Failed to compile YARA rules: {str(e)}")

    def scan_pdf(self, file_path: str) -> Dict:
        """Scan a PDF file using YARA rules only"""
        try:
            yara_matches = self.rules.match(file_path)

            max_weight = max((match.meta.get('weight', 0) for match in yara_matches), default=0)
            threat_level = "high" if max_weight >= 4 else "medium" if max_weight >= 2 else "low"

            return {
                "status": "infected" if threat_level!="low" else "clean",
                "threat_level": threat_level,
                "yara_details": [
                    {"rule": match.rule, "description": match.meta.get('description', 'No description'), "weight": match.meta.get('weight', 0)}
                    for match in yara_matches
                ] if yara_matches else "No YARA threats found",
                "matches_count": len(yara_matches)
            }
        except Exception as e:
            raise Exception(f"Error scanning PDF: {str(e)}")
