from flask import Flask, render_template, request, jsonify
import requests
import hashlib
import re
import time
from datetime import datetime
import json

app = Flask(__name__)

# VirusTotal API Configuration
VT_API_KEY = "5eab21825602e3e6bb6cbb843a1f466ddafdc4cc00e9596f8ffb290ec34e94ff"
VT_BASE_URL = "https://www.virustotal.com/vtapi/v2"

class IOCAnalyzer:
    def __init__(self):
        self.analysis_history = []
    
    def analyze_ioc(self, ioc_value, ioc_type):
        """Main analysis function"""
        result = {
            "ioc": ioc_value,
            "type": ioc_type,
            "timestamp": datetime.now().isoformat(),
            "verdict": "unknown",
            "confidence": 0,
            "sources": [],
            "details": {}
        }
        
        try:
            if ioc_type == "url":
                result = self._analyze_url(ioc_value, result)
            elif ioc_type == "ip":
                result = self._analyze_ip(ioc_value, result)
            elif ioc_type == "domain":
                result = self._analyze_domain(ioc_value, result)
            elif ioc_type == "hash":
                result = self._analyze_hash(ioc_value, result)
            
            # Calculate final verdict
            result = self._calculate_verdict(result)
            
        except Exception as e:
            result["error"] = str(e)
            result["verdict"] = "error"
        
        self.analysis_history.append(result)
        return result
    
    def _analyze_url(self, url, result):
        """Analyze URL using VirusTotal"""
        # VirusTotal URL scan
        vt_result = self._query_virustotal_url(url)
        if vt_result:
            result["sources"].append("VirusTotal")
            result["details"]["virustotal"] = vt_result
            
            # Calculate threat score from VT results
            if "positives" in vt_result and "total" in vt_result:
                positives = vt_result["positives"]
                total = vt_result["total"]
                if total > 0:
                    threat_ratio = positives / total
                    result["confidence"] += min(90, threat_ratio * 100)
        
        # Basic URL analysis
        suspicious_patterns = [
            r'bit\.ly', r'tinyurl', r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
            r'[a-z0-9]{20,}\.com', r'\.tk$', r'\.ml$'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                result["confidence"] += 15
                result["sources"].append("Pattern Analysis")
                break
        
        return result
    
    def _analyze_ip(self, ip, result):
        """Analyze IP address"""
        # VirusTotal IP report
        vt_result = self._query_virustotal_ip(ip)
        if vt_result:
            result["sources"].append("VirusTotal")
            result["details"]["virustotal"] = vt_result
            
            # Check for malicious detections
            if "detected_urls" in vt_result:
                detected = len(vt_result["detected_urls"])
                if detected > 0:
                    result["confidence"] += min(80, detected * 10)
        
        # Basic IP analysis
        private_ranges = [
            r'^10\.', r'^192\.168\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.'
        ]
        
        for pattern in private_ranges:
            if re.match(pattern, ip):
                result["verdict"] = "benign"
                result["confidence"] = 95
                result["sources"].append("Private IP Range")
                break
        
        return result
    
    def _analyze_domain(self, domain, result):
        """Analyze domain name"""
        # VirusTotal domain report
        vt_result = self._query_virustotal_domain(domain)
        if vt_result:
            result["sources"].append("VirusTotal")
            result["details"]["virustotal"] = vt_result
            
            # Check for malicious detections
            if "detected_urls" in vt_result:
                detected = len(vt_result["detected_urls"])
                if detected > 0:
                    result["confidence"] += min(70, detected * 5)
        
        # Domain reputation analysis
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            result["confidence"] += 25
            result["sources"].append("Suspicious TLD")
        
        # Domain age simulation (newer domains more suspicious)
        if len(domain) > 20 or any(char.isdigit() for char in domain):
            result["confidence"] += 15
            result["sources"].append("Domain Analysis")
        
        return result
    
    def _analyze_hash(self, file_hash, result):
        """Analyze file hash"""
        # VirusTotal file report
        vt_result = self._query_virustotal_hash(file_hash)
        if vt_result:
            result["sources"].append("VirusTotal")
            result["details"]["virustotal"] = vt_result
            
            # Calculate threat score from VT results
            if "positives" in vt_result and "total" in vt_result:
                positives = vt_result["positives"]
                total = vt_result["total"]
                if total > 0:
                    threat_ratio = positives / total
                    result["confidence"] += min(95, threat_ratio * 100)
        
        return result
    
    def _query_virustotal_url(self, url):
        """Query VirusTotal URL API"""
        try:
            # First, submit URL for scanning
            params = {
                'apikey': VT_API_KEY,
                'url': url
            }
            
            response = requests.post(f"{VT_BASE_URL}/url/scan", data=params)
            if response.status_code == 200:
                scan_result = response.json()
                
                # Wait a moment then get report
                time.sleep(2)
                
                report_params = {
                    'apikey': VT_API_KEY,
                    'resource': url
                }
                
                report_response = requests.get(f"{VT_BASE_URL}/url/report", params=report_params)
                if report_response.status_code == 200:
                    return report_response.json()
            
        except Exception as e:
            print(f"VirusTotal URL query error: {e}")
        
        return None
    
    def _query_virustotal_ip(self, ip):
        """Query VirusTotal IP API"""
        try:
            params = {
                'apikey': VT_API_KEY,
                'ip': ip
            }
            
            response = requests.get(f"{VT_BASE_URL}/ip-address/report", params=params)
            if response.status_code == 200:
                return response.json()
                
        except Exception as e:
            print(f"VirusTotal IP query error: {e}")
        
        return None
    
    def _query_virustotal_domain(self, domain):
        """Query VirusTotal Domain API"""
        try:
            params = {
                'apikey': VT_API_KEY,
                'domain': domain
            }
            
            response = requests.get(f"{VT_BASE_URL}/domain/report", params=params)
            if response.status_code == 200:
                return response.json()
                
        except Exception as e:
            print(f"VirusTotal Domain query error: {e}")
        
        return None
    
    def _query_virustotal_hash(self, file_hash):
        """Query VirusTotal File Hash API"""
        try:
            params = {
                'apikey': VT_API_KEY,
                'resource': file_hash
            }
            
            response = requests.get(f"{VT_BASE_URL}/file/report", params=params)
            if response.status_code == 200:
                return response.json()
                
        except Exception as e:
            print(f"VirusTotal Hash query error: {e}")
        
        return None
    
    def _calculate_verdict(self, result):
        """Calculate final verdict based on confidence score"""
        confidence = result["confidence"]
        
        if confidence >= 70:
            result["verdict"] = "malicious"
        elif confidence >= 40:
            result["verdict"] = "suspicious"
        elif confidence >= 10:
            result["verdict"] = "unknown"
        else:
            result["verdict"] = "benign"
        
        return result

# Initialize analyzer
analyzer = IOCAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    ioc_value = data.get('ioc', '').strip()
    ioc_type = data.get('type', '')
    
    if not ioc_value or not ioc_type:
        return jsonify({"error": "IOC value and type are required"}), 400
    
    # Analyze the IOC
    result = analyzer.analyze_ioc(ioc_value, ioc_type)
    
    return jsonify(result)

@app.route('/history')
def history():
    return jsonify(analyzer.analysis_history)

@app.route('/report/<int:index>')
def report(index):
    if 0 <= index < len(analyzer.analysis_history):
        return jsonify(analyzer.analysis_history[index])
    return jsonify({"error": "Report not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
