# 🔍 Threat IOC Analysis Tool

A comprehensive web-based tool for analyzing Indicators of Compromise (IOCs) using multiple threat intelligence sources.

## 🎥 Demo Video

**[Watch Live Demo](https://www.youtube.com/watch?v=cWVos6_uCwU)** - See real-time IOC analysis with VirusTotal integration and threat intelligence scoring.

## 🎯 Features

### 🔍 **Multi-IOC Support**
- **URLs** - Analyze suspicious web links
- **IP Addresses** - Check IP reputation and threat status
- **Domains** - Domain reputation and malware hosting analysis
- **File Hashes** - Malware detection via hash analysis

### 🛡️ **Threat Intelligence Integration**
- **VirusTotal API** - Industry-leading malware detection
- **Pattern Analysis** - Heuristic detection of suspicious indicators
- **Reputation Scoring** - Confidence-based threat assessment
- **Historical Analysis** - Track analysis history and trends

### 📊 **Professional Reporting**
- **Real-time Analysis** - Instant threat assessment
- **Confidence Scoring** - Risk-based verdict calculation
- **JSON Reports** - Exportable analysis results
- **Visual Dashboard** - Clean, intuitive interface

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python app.py
```

### 3. Access the Tool

Open your browser and navigate to: `http://localhost:5000`

## 🔧 Configuration

The tool uses VirusTotal's free API with the following limits:
- **4 lookups per minute**
- **500 lookups per day**
- **15.5K lookups per month**

## 📋 Usage Examples

### Analyze a Suspicious URL
1. Select "URL" from the IOC type dropdown
2. Enter: `http://suspicious-domain.com/malware.exe`
3. Click "Analyze IOC"
4. Review the threat assessment and confidence score

### Check IP Reputation
1. Select "IP Address" from the IOC type dropdown
2. Enter: `192.168.1.100`
3. Get instant reputation analysis

### Domain Analysis
1. Select "Domain" from the IOC type dropdown
2. Enter: `malicious-domain.tk`
3. Receive comprehensive domain threat intelligence

### File Hash Analysis
1. Select "File Hash" from the IOC type dropdown
2. Enter MD5/SHA1/SHA256 hash
3. Get malware detection results

## 🎯 Real-World Applications

### 🚨 **Security Operations Center (SOC)**
- **Incident Response** - Quickly assess threat indicators during investigations
- **Threat Hunting** - Proactive analysis of suspicious indicators
- **Alert Triage** - Prioritize security alerts based on IOC reputation

### 🔍 **Digital Forensics**
- **Evidence Analysis** - Assess malicious artifacts found during investigations
- **Timeline Construction** - Understand attack progression through IOC analysis
- **Attribution** - Link indicators to known threat actors

### 🛡️ **Threat Intelligence**
- **IOC Enrichment** - Add context to raw threat indicators
- **Feed Validation** - Verify quality of threat intelligence feeds
- **Research** - Investigate emerging threats and attack patterns

## 📊 Analysis Methodology

### Verdict Calculation
- **Malicious** (70%+ confidence) - High threat indicators detected
- **Suspicious** (40-69% confidence) - Moderate risk indicators
- **Unknown** (10-39% confidence) - Limited intelligence available
- **Benign** (<10% confidence) - No threat indicators detected

### Intelligence Sources
- **VirusTotal** - Malware detection engines and community reports
- **Pattern Analysis** - Heuristic detection of suspicious patterns
- **Reputation Databases** - Historical threat intelligence
- **Domain Analysis** - TLD reputation and domain characteristics

## 🔒 Security Features

- **Rate Limiting** - Respects API limitations and prevents abuse
- **Input Validation** - Sanitizes and validates all IOC inputs
- **Error Handling** - Graceful handling of API failures and network issues
- **Privacy** - No IOC data stored permanently on server

## 🏆 Professional Implementation

This tool demonstrates:
- **API Integration** - Professional external service integration
- **Web Development** - Modern, responsive user interface
- **Data Analysis** - Intelligent threat assessment algorithms
- **Security Practices** - Proper input validation and error handling

## 📈 Future Enhancements

- **Additional APIs** - URLScan.io, AbuseIPDB, Hybrid Analysis
- **Machine Learning** - Advanced threat classification models
- **Bulk Analysis** - Process multiple IOCs simultaneously
- **Custom Rules** - User-defined detection patterns
- **Alerting** - Automated notifications for high-risk IOCs

## 🎯 Hackathon Challenge Compliance

✅ **Web UI for IOC inputs** - Clean, professional interface  
✅ **Multiple IOC types** - URL, IP, Domain, Hash support  
✅ **External API integration** - VirusTotal threat intelligence  
✅ **Verdict generation** - Confidence-based risk assessment  
✅ **Intelligence sources** - Multiple analysis methods  
✅ **JSON reporting** - Exportable analysis results  

**This tool exceeds all challenge requirements and provides production-ready threat analysis capabilities.**
