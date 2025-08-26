from flask import Flask, request, jsonify, render_template, send_file
from dotenv import load_dotenv
from pathlib import Path
import os
import requests
import tempfile
import json
import datetime
import time
import base64
import re
import ipaddress
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from urllib.parse import urlparse

app = Flask(__name__)

# Always load .env from the same folder as app.py
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

def require_env(key_name: str) -> str:
    try:
        val = os.environ.get(key_name)
        if not val:
            raise KeyError(f"Missing environment variable: {key_name}")
        return val
    except Exception as e:
        raise RuntimeError(str(e))

API_KEYS = {
    'VT_API_KEY': require_env('VT_API_KEY'),
    'ABUSEIPDB_KEY': require_env('ABUSEIPDB_KEY'),
    'GREYNOISE_KEY': require_env('GREYNOISE_KEY'),
    'IPINFO_TOKEN': require_env('IPINFO_TOKEN'),
    'SHODAN_API_KEY': require_env('SHODAN_API_KEY'),
    'IPREGISTRY_KEY': require_env('IPREGISTRY_KEY'),
    'WHOISXMLAPI_KEY': require_env('WHOISXMLAPI_KEY'),
    'PULSEDIVE_KEY': require_env('PULSEDIVE_KEY'),
    'NEWS_API_KEY': require_env('NEWS_API_KEY'),
}


news_cache = {
    'timestamp': None,
    'data': None
}
VT_API_URL = 'https://www.virustotal.com/api/v3'
PULSEDIVE_API_URL = 'https://pulsedive.com/api/info.php'

def is_private_ip(ip):
    """Check if an IP address is private/reserved"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
    except ValueError:
        return False

def is_private_url(url):
    """Check if a URL points to a private/reserved IP address"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        # Check if it's an IP address
        if hostname and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            return is_private_ip(hostname)
        
        # Check for localhost or local domain
        if hostname and (hostname.lower().endswith('.local') or hostname.lower() == 'localhost'):
            return True
            
        return False
    except:
        return False

def poll_vt_analysis(analysis_id):
    """Poll VirusTotal analysis until completion"""
    max_attempts = 10
    interval = 15  
    
    for _ in range(max_attempts):
        time.sleep(interval)
        try:
            response = requests.get(
                f'{VT_API_URL}/analyses/{analysis_id}',
                headers={'x-apikey': API_KEYS['VT_API_KEY']}
            )
            
            if response.status_code == 200:
                data = response.json()
                status = data.get('data', {}).get('attributes', {}).get('status')
                if status == 'completed':
                    return data
        except Exception as e:
            print(f"Polling error: {e}")
            continue
    
    return None

# VirusTotal File Scan
@app.route('/vt/scan', methods=['POST'])
def vt_scan():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Save to temp file
    temp_path = os.path.join(tempfile.gettempdir(), file.filename)
    file.save(temp_path)
    
    try:
        # Upload file to VirusTotal
        with open(temp_path, 'rb') as f:
            files = {'file': (file.filename, f)}
            response = requests.post(
                f'{VT_API_URL}/files',
                headers={'x-apikey': API_KEYS['VT_API_KEY']},
                files=files
            )
        
        if response.status_code != 200:
            return jsonify({'error': 'Upload failed', 'details': response.json()}), 500
        
        # Get analysis ID
        analysis_id = response.json().get('data', {}).get('id')
        if not analysis_id:
            return jsonify({'error': 'Invalid response from VirusTotal'}), 500
        
        # Poll for analysis results
        analysis_data = poll_vt_analysis(analysis_id)
        if not analysis_data:
            return jsonify({'error': 'Analysis did not complete in time'}), 504
        
        # Get full file report using SHA256
        file_id = analysis_data.get('meta', {}).get('file_info', {}).get('sha256')
        if file_id:
            report_response = requests.get(
                f'{VT_API_URL}/files/{file_id}',
                headers={'x-apikey': API_KEYS['VT_API_KEY']}
            )
            if report_response.status_code == 200:
                return report_response.json()
        
        return analysis_data
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

# VirusTotal URL Scan
@app.route('/vt/url', methods=['POST'])
def vt_url():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    # Check for private URL
    if is_private_url(url):
        return jsonify({
            'error': 'Private URL detected',
            'message': 'VirusTotal cannot scan private/internal URLs. Please use a public URL.'
        }), 400
    
    try:
        # Submit URL for scanning
        response = requests.post(
            f'{VT_API_URL}/urls',
            headers={'x-apikey': API_KEYS['VT_API_KEY']},
            data={'url': url}
        )
        
        if response.status_code != 200:
            return jsonify({'error': 'Submission failed', 'details': response.json()}), 500
        
        # Get analysis ID
        analysis_id = response.json().get('data', {}).get('id')
        if not analysis_id:
            return jsonify({'error': 'Invalid response from VirusTotal'}), 500
        
        # Poll for analysis results
        analysis_data = poll_vt_analysis(analysis_id)
        if not analysis_data:
            return jsonify({'error': 'Analysis did not complete in time'}), 504
        
        # Get URL report using base64 encoded URL
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        report_response = requests.get(
            f'{VT_API_URL}/urls/{url_id}',
            headers={'x-apikey': API_KEYS['VT_API_KEY']}
        )
        
        if report_response.status_code == 200:
            return report_response.json()
        
        return analysis_data
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# OSINT APIs
@app.route('/osint/<service>', methods=['POST'])
def osint_lookup(service):
    target = request.form.get('target')
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # Check for private IP
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target) and is_private_ip(target):
        return jsonify({
            'error': 'Private IP detected',
            'message': 'OSINT services cannot lookup private/internal IP addresses. Please use a public IP.',
            'private_info': {
                'ip': target,
                'category': 'Private/Internal',
                'common_use': 'Local network devices',
                'suggestion': 'This IP is not routable on the public internet'
            }
        }), 400
    
    try:
        if service == 'abuseipdb':
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check?ipAddress={target}',
                headers={'Key': API_KEYS['ABUSEIPDB_KEY'], 'Accept': 'application/json'}
            )
            data = response.json()
            # Extract important fields
            result = {
                'service': 'AbuseIPDB',
                'ip': data['data']['ipAddress'],
                'abuse_score': data['data']['abuseConfidenceScore'],
                'country': data['data']['countryCode'],
                'usage_type': data['data']['usageType'],
                'isp': data['data']['isp'],
                'domain': data['data']['domain'],
                'last_reported': data['data']['lastReportedAt']
            }
            return jsonify(result)
        
        elif service == 'greynoise':
            response = requests.get(
                f'https://api.greynoise.io/v3/community/{target}',
                headers={'key': API_KEYS['GREYNOISE_KEY']}
            )
            data = response.json()
            # Extract important fields
            result = {
                'service': 'GreyNoise',
                'ip': target,
                'classification': data.get('classification'),
                'name': data.get('name'),
                'link': data.get('link'),
                'last_seen': data.get('last_seen'),
                'noise': data.get('noise'),
                'riot': data.get('riot')
            }
            return jsonify(result)
        
        elif service == 'ipinfo':
            response = requests.get(
                f'https://ipinfo.io/{target}/json?token={API_KEYS["IPINFO_TOKEN"]}'
            )
            data = response.json()
            # Extract important fields
            result = {
                'service': 'IPInfo',
                'ip': data.get('ip'),
                'host': data.get('hostname'),
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country'),
                'loc': data.get('loc'),
                'org': data.get('org'),
                'postal': data.get('postal'),
                'timezone': data.get('timezone')
            }
            return jsonify(result)
        
        elif service == 'shodan':
            response = requests.get(
                f'https://api.shodan.io/shodan/host/{target}?key={API_KEYS["SHODAN_API_KEY"]}'
            )
            data = response.json()
            # Extract important fields
            result = {
                'service': 'Shodan',
                'ip': data.get('ip_str'),
                'ports': data.get('ports'),
                'hostnames': data.get('hostnames'),
                'domains': data.get('domains'),
                'org': data.get('org'),
                'os': data.get('os'),
                'vulnerabilities': list(data.get('vulns', {}).keys()) if 'vulns' in data else [],
                'location': {
                    'city': data.get('city'),
                    'country': data.get('country_name'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude')
                }
            }
            return jsonify(result)
        
        elif service == 'ipregistry':
            response = requests.get(
                f'https://api.ipregistry.co/{target}?key={API_KEYS["IPREGISTRY_KEY"]}'
            )
            data = response.json()
            # Extract important fields
            result = {
                'service': 'IPRegistry',
                'ip': data.get('ip'),
                'type': data.get('type'),
                'hostname': data.get('hostname'),
                'location': {
                    'city': data.get('location', {}).get('city'),
                    'region': data.get('location', {}).get('region', {}).get('name'),
                    'country': data.get('location', {}).get('country', {}).get('name'),
                    'continent': data.get('location', {}).get('continent', {}).get('name'),
                    'latitude': data.get('location', {}).get('latitude'),
                    'longitude': data.get('location', {}).get('longitude')
                },
                'security': {
                    'is_abuser': data.get('security', {}).get('is_abuser'),
                    'is_attacker': data.get('security', {}).get('is_attacker'),
                    'is_threat': data.get('security', {}).get('is_threat'),
                    'is_tor': data.get('security', {}).get('is_tor')
                }
            }
            return jsonify(result)
        
        elif service == 'whoisxml':
            # Check if target is IP or domain
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, target):
                # IP address lookup
                response = requests.get(f'https://ipwhois.app/json/{target}')
                if response.status_code == 200:
                    data = response.json()
                    result = {
                        'service': 'WhoisXML',
                        'type': 'IP Address',
                        'ip': target,
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'continent': data.get('continent'),
                        'country': data.get('country'),
                        'region': data.get('region'),
                        'city': data.get('city'),
                        'timezone': data.get('timezone'),
                        'asn': data.get('asn'),
                        'latitude': data.get('latitude'),
                        'longitude': data.get('longitude'),
                        'security': {
                            'proxy': data.get('proxy'),
                            'tor': data.get('tor'),
                            'mobile': data.get('mobile')
                        }
                    }
                    return jsonify(result)
                else:
                    return jsonify({'error': 'IP lookup failed'}), 500
            else:
                # Domain lookup
                response = requests.get(
                    f'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={API_KEYS["WHOISXMLAPI_KEY"]}&domainName={target}&outputFormat=JSON'
                )
                data = response.json()
                # Extract important fields
                registrant = data.get('WhoisRecord', {}).get('registrant', {})
                admin = data.get('WhoisRecord', {}).get('administrativeContact', {})
                tech = data.get('WhoisRecord', {}).get('technicalContact', {})
                
                # Get name servers
                ns = data.get('WhoisRecord', {}).get('nameServers', {})
                name_servers = ns.get('hostNames', []) if ns else []
                
                result = {
                    'service': 'WhoisXML',
                    'type': 'Domain',
                    'domain': data.get('WhoisRecord', {}).get('domainName'),
                    'created': data.get('WhoisRecord', {}).get('createdDate'),
                    'updated': data.get('WhoisRecord', {}).get('updatedDate'),
                    'expires': data.get('WhoisRecord', {}).get('expiresDate'),
                    'registrar': data.get('WhoisRecord', {}).get('registrarName'),
                    'name_servers': name_servers,
                    'status': data.get('WhoisRecord', {}).get('status'),
                    'contact': {
                        'registrant': registrant.get('name'),
                        'admin': admin.get('name'),
                        'tech': tech.get('name'),
                        'email': registrant.get('email') or admin.get('email') or tech.get('email'),
                        'organization': registrant.get('organization') or admin.get('organization') or tech.get('organization')
                    }
                }
                return jsonify(result)
        
        elif service == 'pulsedive':
            # Pulsedive API lookup
            params = {
                'indicator': target,
                'get': 'links,properties',
                'pretty': 1,
                'key': API_KEYS['PULSEDIVE_KEY']
            }
            response = requests.get(PULSEDIVE_API_URL, params=params)
            data = response.json()
            
            # Process the response
            if 'error' in data:
                return jsonify({'error': data['error']}), 400
                
            result = {
                'service': 'Pulsedive',
                'indicator': data.get('indicator'),
                'type': data.get('type'),
                'risk': data.get('risk'),
                'risk_recommended': data.get('risk_recommended'),
                'stamp_seen': data.get('stamp_seen'),
                'stamp_updated': data.get('stamp_updated'),
                'retired': data.get('retired'),
                'properties': data.get('properties', {}),
                'threats': data.get('threats', []),
                'feeds': data.get('feeds', []),
                'references': data.get('references', [])
            }
            
            # Add linked indicators if available
            if 'related' in data:
                result['parents'] = data['related'].get('parents', [])
                result['children'] = data['related'].get('children', [])
                
            return jsonify(result)
        
        else:
            return jsonify({'error': 'Invalid service'}), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Fetch recent AbuseIPDB reports by country
@app.route('/abuseipdb/recent/<country_code>', methods=['GET'])
def abuseipdb_recent(country_code):
    """Get recent abuse reports for a specific country"""
    try:
        # Validate country code
        if not re.match(r'^[A-Z]{2}$', country_code):
            return jsonify({'error': 'Invalid country code format. Use ISO 3166-1 alpha-2 format'}), 400
        
        # Set default parameters
        params = {
            'countryCode': country_code,
            'limit': 10,  # Get top 10 recent reports
            'maxAgeInDays': 30  # Last 30 days
        }
        
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/country-reports',
            headers={'Key': API_KEYS['ABUSEIPDB_KEY'], 'Accept': 'application/json'},
            params=params
        )
        
        if response.status_code != 200:
            return jsonify({'error': 'Failed to fetch recent reports', 'details': response.json()}), 500
        
        data = response.json()
        return jsonify({
            'country': country_code,
            'recent_reports': data.get('data', {}).get('reports', [])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/news/cyber', methods=['GET'])
def cyber_news():
    """Get recent cybersecurity news articles"""
    try:
        # Check if we have cached news that's less than 1 hour old
        if news_cache['timestamp'] and (datetime.datetime.now() - news_cache['timestamp']).seconds < 3600:
            return jsonify(news_cache['data'])
        
        # Calculate date range for news (last 48 hours)
        two_days_ago = (datetime.datetime.now() - datetime.timedelta(days=2)).strftime('%Y-%m-%d')
        
        params = {
            'apiKey': API_KEYS['NEWS_API_KEY'],
            'q': 'cybersecurity OR cyberattack OR hacking OR malware OR phishing OR ransomware OR "data breach" OR "security vulnerability"',
            'pageSize': 8,
            'language': 'en',
            'sortBy': 'publishedAt',
            'from': two_days_ago
        }
        
        response = requests.get('https://newsapi.org/v2/everything', params=params)
        
        if response.status_code != 200:
            return jsonify({'error': 'Failed to fetch news', 'details': response.json()}), 500
        
        data = response.json()
        
        # Filter only cybersecurity-related news
        cyber_keywords = ['cyber', 'hack', 'breach', 'ransom', 'phish', 'malware', 'security', 'vulnerability']
        filtered_articles = [
            article for article in data.get('articles', [])
            if any(keyword in article.get('title', '').lower() or 
                   keyword in article.get('description', '').lower()
                   for keyword in cyber_keywords)
        ]
        
        # Limit to 5 articles
        filtered_articles = filtered_articles[:5]
        
        result = {
            'status': 'success',
            'articles': filtered_articles,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Update cache
        news_cache['timestamp'] = datetime.datetime.now()
        news_cache['data'] = result
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# PDF Generator
@app.route('/download-report', methods=['POST'])
def download_report():
    data = request.form.get('data')
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        # Create PDF in memory
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # Add content
        p.setFont("Helvetica", 12)
        text = p.beginText(40, height - 40)
        
        # Format JSON data
        try:
            json_data = json.loads(data)
            formatted = json.dumps(json_data, indent=2)
        except:
            formatted = data
        
        # Split into lines
        for line in formatted.splitlines():
            text.textLine(line)
        
        p.drawText(text)
        p.showPage()
        p.save()
        
        # Return PDF
        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name='osint_report.pdf',
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/debug-template')
def debug_template():
    p = Path(__file__).resolve().parent / 'templates' / 'index.html'
    if not p.exists():
        return "index.html NOT FOUND", 404
    data = p.read_bytes()
    head = data[:16]
    return f"Found index.html ({len(data)} bytes); head16={head.hex()}"
@app.route('/')
def index():
    return render_template('index.html')
if __name__ == '__main__':
    app.run(debug=True)
