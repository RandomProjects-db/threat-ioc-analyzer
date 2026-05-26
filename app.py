import os
import re
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

VT_API_KEY = os.environ.get("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/vtapi/v2"


class IOCAnalyzer:
    def __init__(self):
        self.analysis_history = []

    def analyze_ioc(self, ioc_value: str, ioc_type: str) -> dict:
        result = {
            "ioc": ioc_value,
            "type": ioc_type,
            "timestamp": datetime.now().isoformat(),
            "verdict": "unknown",
            "confidence": 0,
            "sources": [],
            "details": {},
        }

        handlers = {
            "url": self._analyze_url,
            "ip": self._analyze_ip,
            "domain": self._analyze_domain,
            "hash": self._analyze_hash,
        }

        handler = handlers.get(ioc_type)
        if not handler:
            result["error"] = f"Unsupported IOC type: {ioc_type}"
            return result

        try:
            result = handler(ioc_value, result)
            result = self._calculate_verdict(result)
        except requests.RequestException as e:
            result["error"] = f"API request failed: {e}"
            result["verdict"] = "error"
        except Exception as e:
            result["error"] = str(e)
            result["verdict"] = "error"

        self.analysis_history.append(result)
        return result

    def _analyze_url(self, url: str, result: dict) -> dict:
        vt_result = self._vt_request("url", url)
        if vt_result:
            result["sources"].append("VirusTotal")
            result["details"]["virustotal"] = vt_result
            result["confidence"] += self._score_from_detections(vt_result)

        suspicious_patterns = [
            r'bit\.ly', r'tinyurl', r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'[a-z0-9]{20,}\.com', r'\.(tk|ml|ga|cf|pw)$'
        ]
        if any(re.search(p, url, re.IGNORECASE) for p in suspicious_patterns):
            result["confidence"] += 15
            result["sources"].append("Pattern Analysis")

        return result

    def _analyze_ip(self, ip: str, result: dict) -> dict:
        if re.match(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)', ip):
            result["verdict"] = "benign"
            result["confidence"] = 95
            result["sources"].append("Private IP Range")
            return result

        vt_result = self._vt_request("ip", ip)
        if vt_result:
            result["sources"].append("VirusTotal")
            result["details"]["virustotal"] = vt_result
            detected = len(vt_result.get("detected_urls", []))
            if detected > 0:
                result["confidence"] += min(80, detected * 10)

        return result

    def _analyze_domain(self, domain: str, result: dict) -> dict:
        vt_result = self._vt_request("domain", domain)
        if vt_result:
            result["sources"].append("VirusTotal")
            result["details"]["virustotal"] = vt_result
            detected = len(vt_result.get("detected_urls", []))
            if detected > 0:
                result["confidence"] += min(70, detected * 5)

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            result["confidence"] += 25
            result["sources"].append("Suspicious TLD")

        if len(domain) > 20 or re.search(r'\d', domain):
            result["confidence"] += 15
            result["sources"].append("Domain Analysis")

        return result

    def _analyze_hash(self, file_hash: str, result: dict) -> dict:
        vt_result = self._vt_request("hash", file_hash)
        if vt_result:
            result["sources"].append("VirusTotal")
            result["details"]["virustotal"] = vt_result
            result["confidence"] += self._score_from_detections(vt_result, cap=95)

        return result

    def _vt_request(self, ioc_type: str, value: str) -> dict | None:
        if not VT_API_KEY:
            return None

        try:
            if ioc_type == "url":
                requests.post(f"{VT_BASE_URL}/url/scan", data={"apikey": VT_API_KEY, "url": value})
                time.sleep(2)
                r = requests.get(f"{VT_BASE_URL}/url/report", params={"apikey": VT_API_KEY, "resource": value}, timeout=10)
            elif ioc_type == "ip":
                r = requests.get(f"{VT_BASE_URL}/ip-address/report", params={"apikey": VT_API_KEY, "ip": value}, timeout=10)
            elif ioc_type == "domain":
                r = requests.get(f"{VT_BASE_URL}/domain/report", params={"apikey": VT_API_KEY, "domain": value}, timeout=10)
            elif ioc_type == "hash":
                r = requests.get(f"{VT_BASE_URL}/file/report", params={"apikey": VT_API_KEY, "resource": value}, timeout=10)
            else:
                return None

            if r.status_code == 200:
                return r.json()
            if r.status_code == 204:
                time.sleep(15)  # Rate limited, wait and retry once
                r = requests.get(r.url, timeout=10)
                return r.json() if r.status_code == 200 else None
        except requests.RequestException:
            pass
        return None

    def _score_from_detections(self, vt_result: dict, cap: int = 90) -> int:
        positives = vt_result.get("positives", 0)
        total = vt_result.get("total", 0)
        if total == 0:
            return 0
        return min(cap, int((positives / total) * 100))

    def _calculate_verdict(self, result: dict) -> dict:
        c = result["confidence"]
        if c >= 70:
            result["verdict"] = "malicious"
        elif c >= 40:
            result["verdict"] = "suspicious"
        elif c >= 10:
            result["verdict"] = "unknown"
        else:
            result["verdict"] = "benign"
        return result


analyzer = IOCAnalyzer()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    ioc_value = data.get('ioc', '').strip()
    ioc_type = data.get('type', '').strip()

    if not ioc_value or not ioc_type:
        return jsonify({"error": "IOC value and type are required"}), 400

    if ioc_type not in ("url", "ip", "domain", "hash"):
        return jsonify({"error": f"Invalid type: {ioc_type}"}), 400

    result = analyzer.analyze_ioc(ioc_value, ioc_type)
    return jsonify(result)


@app.route('/history')
def history():
    return jsonify(analyzer.analysis_history[-50:])  # Last 50 only


@app.route('/report/<int:index>')
def report(index):
    if 0 <= index < len(analyzer.analysis_history):
        return jsonify(analyzer.analysis_history[index])
    return jsonify({"error": "Report not found"}), 404


if __name__ == '__main__':
    if not VT_API_KEY:
        print("WARNING: VT_API_KEY not set. VirusTotal lookups will be skipped.")
    app.run(debug=True, host='0.0.0.0', port=5001)
