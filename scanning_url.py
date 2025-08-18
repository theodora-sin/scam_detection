import base64
import requests

def check_url_virustotal(url: str, api_key: str) -> dict:
    """
    VirusTotal URL report using VT v3.
    - Provide api_key via env: VIRUSTOTAL_API_KEY
    """
    if not api_key:
        return {'status': 'error', 'details': 'VirusTotal API key not configured', 'score': 0}

    try:
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {'x-apikey': api_key}
        r = requests.get(f'https://www.virustotal.com/api/v3/urls/{encoded}', headers=headers, timeout=15)

        if r.status_code == 200:
            j = r.json()
            if 'data' in j:
                stats = j['data']['attributes']['last_analysis_stats']
                mal = stats.get('malicious', 0)
                susp = stats.get('suspicious', 0)
                clean = stats.get('harmless', 0)
                und = stats.get('undetected', 0)
                total = mal + susp + clean + und
                score = 0
                if total > 0:
                    risk_pct = ((mal*2 + susp) / total) * 100
                    score = min(int(risk_pct * 1.5), 100)
                if mal > 0: status = 'dangerous'
                elif susp > 0: status = 'suspicious'
                elif clean > 0: status = 'safe'
                else: status = 'unknown'
                return {
                    'status': status, 'details': stats, 'score': score,
                    'malicious_engines': mal, 'suspicious_engines': susp,
                    'clean_engines': clean, 'total_engines': total,
                    'analysis_date': j['data']['attributes'].get('last_analysis_date', 'Unknown')
                }
            return {'status': 'not_found', 'details': 'URL not found', 'score': 0}
        if r.status_code == 404:
            return {'status': 'not_found', 'details': 'URL not in VT db', 'score': 0}
        if r.status_code == 429:
            return {'status': 'rate_limited', 'details': 'Rate limit exceeded', 'score': 25}
        return {'status': 'error', 'details': f'VT status {r.status_code}', 'score': 25}
    except requests.exceptions.Timeout:
        return {'status': 'timeout', 'details': 'VT request timed out', 'score': 25}
    except requests.exceptions.RequestException as e:
        return {'status': 'network_error', 'details': f'Network error: {e}', 'score': 25}
    except Exception as e:
        return {'status': 'error', 'details': f'Unexpected error: {e}', 'score': 25}


