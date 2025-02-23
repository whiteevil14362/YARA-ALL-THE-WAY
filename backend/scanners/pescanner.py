import os
import re
import hashlib
import pefile
import yara
import math
from collections import Counter

class PEScanner:
    SUSPICIOUS_STRINGS = [
        rb"http://", rb"https://", 
        rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  
        rb"eval\(", rb"unescape\(",  
        rb"powershell", rb"cmd\.exe",  
        rb"CreateRemoteThread", rb"VirtualAlloc",  
    ]
    SUSPICIOUS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_STRINGS]
    
    def __init__(self, yara_rule_path=None):
        self.yara_rules = None
        if yara_rule_path and os.path.exists(yara_rule_path):
            try:
                self.yara_rules = yara.compile(filepath=yara_rule_path)
            except yara.SyntaxError as e:
                print(f"❌ YARA Syntax Error: {e}")
    
    def calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return None
        return sha256_hash.hexdigest()
    
    def calculate_entropy(self, data):
        if not data:
            return 0.0
        byte_counts = Counter(data)
        total_bytes = len(data)
        return -sum((count / total_bytes) * math.log2(count / total_bytes) for count in byte_counts.values())
    
    def search_suspicious_strings(self, file_path):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            return [pattern.pattern.decode() for pattern in self.SUSPICIOUS_PATTERNS if pattern.search(content)]
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return []
    
    def get_imphash(self, file_path):
        try:
            pe = pefile.PE(file_path)
            return pe.get_imphash()
        except pefile.PEFormatError:
            return None
    
    def analyze_pe_file(self, file_path):
        try:
            pe = pefile.PE(file_path)
            indicators = []
            
            suspicious_sections = [b".upx", b".overlay", b".packed", b".data", b".text"]
            for section in pe.sections:
                sec_name = section.Name.strip(b"\x00").lower()
                entropy = self.calculate_entropy(section.get_data())
                if sec_name in suspicious_sections or entropy > 7.0:
                    indicators.append(f"⚠ Suspicious section: {sec_name.decode()} (Entropy: {entropy:.2f})")
            
            suspicious_imports = ["CreateRemoteThread", "VirtualAlloc", "LoadLibrary"]
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    for imp in entry.imports:
                        if imp.name and imp.name.decode() in suspicious_imports:
                            indicators.append(f"🚨 Suspicious API: {dll_name}!{imp.name.decode()}")
            
            return indicators
        except pefile.PEFormatError:
            return []
    
    def scan_with_yara(self, file_path):
        if self.yara_rules:
            try:
                return self.yara_rules.match(file_path)
            except Exception as e:
                print(f"❌ YARA scan failed: {e}")
                return None
        return None


    def scan_file(self, file_path):
        """Perform a full static analysis scan on a file."""
        report = {
            "sha256": self.calculate_file_hash(file_path),
            "imphash": self.get_imphash(file_path),
            "suspicious_strings": self.search_suspicious_strings(file_path),
            "pe_analysis": self.analyze_pe_file(file_path) if file_path.lower().endswith((".exe", ".dll")) else [],
            "yara_matches": []
        }
        
        # Perform YARA scan if rules are available
        if self.yara_rules:
            report["yara_matches"] = [match.rule for match in self.scan_with_yara(file_path)]

        
        # Set threat level based on YARA matches
        report["threat_level"] = "high" if report["yara_matches"] else "low"
        report["status"] = "clean" if report["threat_level"]=="low" else "infected"
        
        return report


