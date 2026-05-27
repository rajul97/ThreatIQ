import os
import time
import base64
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

logger = logging.getLogger('threatiq')

# ── Constants ──────────────────────────────────────────────────
TIMEOUT        = 8
MAX_WORKERS    = 10
RETRY_ATTEMPTS = 2
RETRY_DELAY    = 1.0

# ── API Keys ───────────────────────────────────────────────────
OTX_KEY        = os.getenv('OTX_API_KEY', '')
GREYNOISE_KEY  = os.getenv('GREYNOISE_API_KEY', '')
URLSCAN_KEY    = os.getenv('URLSCAN_API_KEY', '')
VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
ABUSEIPDB_KEY  = os.getenv('ABUSEIPDB_API_KEY', '')
HYBRID_KEY     = os.getenv('HYBRID_ANALYSIS_API_KEY', '')


# ── HTTP Helpers ───────────────────────────────────────────────

def _get(url: str, headers: Dict = None, params: Dict = None,
         retries: int = RETRY_ATTEMPTS) -> Optional[Dict]:
    for attempt in range(retries):
        try:
            resp = requests.get(
                url, headers=headers or {}, params=params or {},
                timeout=TIMEOUT
            )
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 429:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            return None
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on {url} (attempt {attempt + 1})")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error on {url}")
        except Exception as e:
            logger.error(f"Request error {url}: {e}")
        if attempt < retries - 1:
            time.sleep(RETRY_DELAY)
    return None


def _post(url: str, data: Dict = None, headers: Dict = None) -> Optional[Dict]:
    """POST with application/x-www-form-urlencoded (MalwareBazaar, URLhaus, HybridAnalysis)."""
    try:
        resp = requests.post(
            url, data=data or {}, headers=headers or {}, timeout=TIMEOUT
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as e:
        logger.error(f"POST error {url}: {e}")
        return None


def _post_json(url: str, payload: Dict = None, headers: Dict = None) -> Optional[Dict]:
    """
    FIX: POST with application/json body.
    ThreatFox API v1 requires JSON — not form-encoded data.
    """
    try:
        resp = requests.post(
            url, json=payload or {}, headers=headers or {}, timeout=TIMEOUT
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as e:
        logger.error(f"POST JSON error {url}: {e}")
        return None


# ══════════════════════════════════════════════════════════════
# INDIVIDUAL API VALIDATORS
# ══════════════════════════════════════════════════════════════

def _otx_ip(ip: str) -> Dict:
    if not OTX_KEY:
        return {'source': 'otx', 'skipped': True}
    headers = {'X-OTX-API-KEY': OTX_KEY}
    data = _get(f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general', headers)
    if not data:
        return {'source': 'otx', 'error': True}
    pulses = data.get('pulse_info', {}).get('count', 0)
    return {
        'source': 'otx',
        'found': pulses > 0,
        'pulse_count': pulses,
        'threat_score': data.get('pulse_info', {}).get('related_indicator_is_malicious', False),
        'country': data.get('country_code', 'Unknown'),
        'asn': data.get('asn', 'Unknown'),
        'reputation': data.get('reputation', 0),
    }


def _otx_domain(domain: str) -> Dict:
    if not OTX_KEY:
        return {'source': 'otx', 'skipped': True}
    headers = {'X-OTX-API-KEY': OTX_KEY}
    data = _get(f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general', headers)
    if not data:
        return {'source': 'otx', 'error': True}
    pulses = data.get('pulse_info', {}).get('count', 0)
    return {
        'source': 'otx',
        'found': pulses > 0,
        'pulse_count': pulses,
        'alexa_rank': data.get('alexa', 'Unknown'),
        'whois': data.get('whois', ''),
    }


def _otx_hash(hash_val: str) -> Dict:
    if not OTX_KEY:
        return {'source': 'otx', 'skipped': True}
    headers = {'X-OTX-API-KEY': OTX_KEY}
    data = _get(
        f'https://otx.alienvault.com/api/v1/indicators/file/{hash_val}/general',
        headers
    )
    if not data:
        return {'source': 'otx', 'error': True}
    pulses = data.get('pulse_info', {}).get('count', 0)
    return {
        'source': 'otx',
        'found': pulses > 0,
        'pulse_count': pulses,
        'malware_family': data.get('malware_families', []),
    }


def _malwarebazaar(hash_val: str) -> Dict:
    # MalwareBazaar uses form-encoded POST — _post() is correct here
    data = _post(
        'https://mb-api.abuse.ch/api/v1/',
        data={'query': 'get_info', 'hash': hash_val}
    )
    if not data or data.get('query_status') != 'hash_found':
        return {'source': 'malwarebazaar', 'found': False}
    info = data.get('data', [{}])[0]
    return {
        'source': 'malwarebazaar',
        'found': True,
        'malware_family': info.get('signature', 'Unknown'),
        'file_type': info.get('file_type', 'Unknown'),
        'first_seen': info.get('first_seen', 'Unknown'),
        'tags': info.get('tags', []),
        'reporter': info.get('reporter', 'Unknown'),
    }


def _urlhaus_url(url: str) -> Dict:
    # URLhaus uses form-encoded POST
    data = _post('https://urlhaus-api.abuse.ch/v1/url/', data={'url': url})
    if not data or data.get('query_status') != 'is_listed':
        return {'source': 'urlhaus', 'found': False}
    return {
        'source': 'urlhaus',
        'found': True,
        'threat': data.get('threat', 'Unknown'),
        'url_status': data.get('url_status', 'Unknown'),
        'date_added': data.get('date_added', 'Unknown'),
        'tags': data.get('tags', []),
        'payloads': len(data.get('payloads', []) or []),
    }


def _urlhaus_domain(domain: str) -> Dict:
    data = _post('https://urlhaus-api.abuse.ch/v1/host/', data={'host': domain})
    if not data or data.get('query_status') != 'is_listed':
        return {'source': 'urlhaus', 'found': False}
    return {
        'source': 'urlhaus',
        'found': True,
        'urls_count': data.get('urls_count', 0),
        'blacklists': data.get('blacklists', {}),
    }


def _threatfox(ioc: str) -> Dict:
    # FIX: ThreatFox API v1 requires JSON body, not form-encoded
    payload = {'query': 'search_ioc', 'search_term': ioc}
    data = _post_json('https://threatfox-api.abuse.ch/api/v1/', payload)
    if not data or data.get('query_status') != 'ok':
        return {'source': 'threatfox', 'found': False}
    results = data.get('data', [])
    if not results:
        return {'source': 'threatfox', 'found': False}
    top = results[0]
    return {
        'source': 'threatfox',
        'found': True,
        'ioc_type': top.get('ioc_type', 'Unknown'),
        'threat_type': top.get('threat_type', 'Unknown'),
        'malware': top.get('malware', 'Unknown'),
        'confidence': top.get('confidence_level', 0),
        'first_seen': top.get('first_seen', 'Unknown'),
        'tags': top.get('tags', []),
    }


def _greynoise(ip: str) -> Dict:
    if not GREYNOISE_KEY:
        return {'source': 'greynoise', 'skipped': True}
    headers = {'key': GREYNOISE_KEY, 'Accept': 'application/json'}
    data = _get(f'https://api.greynoise.io/v3/community/{ip}', headers)
    if not data:
        return {'source': 'greynoise', 'error': True}
    return {
        'source': 'greynoise',
        'found': True,
        'noise': data.get('noise', False),
        'riot': data.get('riot', False),
        'classification': data.get('classification', 'unknown'),
        'name': data.get('name', 'Unknown'),
        'last_seen': data.get('last_seen', 'Unknown'),
        'message': data.get('message', ''),
    }


def _urlscan(url: str) -> Dict:
    if not URLSCAN_KEY:
        return {'source': 'urlscan', 'skipped': True}
    headers = {'API-Key': URLSCAN_KEY, 'Content-Type': 'application/json'}
    # URL-encode the search query properly
    import urllib.parse
    encoded = urllib.parse.quote(url, safe='')
    search_data = _get(
        f'https://urlscan.io/api/v1/search/?q=page.url:{encoded}&size=1',
        headers
    )
    if not search_data or not search_data.get('results'):
        return {'source': 'urlscan', 'found': False}
    result = search_data['results'][0]
    return {
        'source': 'urlscan',
        'found': True,
        'verdict': result.get('verdicts', {}).get('overall', {}).get('score', 0),
        'malicious': result.get('verdicts', {}).get('overall', {}).get('malicious', False),
        'screenshot': result.get('screenshot', ''),
        'domain': result.get('page', {}).get('domain', ''),
        'country': result.get('page', {}).get('country', 'Unknown'),
    }


def _ipapi(ip: str) -> Dict:
    data = _get(
        f'http://ip-api.com/json/{ip}',
        params={'fields': 'status,country,countryCode,region,city,isp,org,as,proxy,hosting'}
    )
    if not data or data.get('status') != 'success':
        return {'source': 'ip-api', 'error': True}
    return {
        'source': 'ip-api',
        'found': True,
        'country': data.get('country', 'Unknown'),
        'country_code': data.get('countryCode', ''),
        'city': data.get('city', 'Unknown'),
        'isp': data.get('isp', 'Unknown'),
        'org': data.get('org', 'Unknown'),
        'asn': data.get('as', 'Unknown'),
        'is_proxy': data.get('proxy', False),
        'is_hosting': data.get('hosting', False),
    }


def _virustotal_ip(ip: str) -> Dict:
    if not VIRUSTOTAL_KEY:
        return {'source': 'virustotal', 'skipped': True}
    headers = {'x-apikey': VIRUSTOTAL_KEY}
    data = _get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}', headers)
    if not data:
        return {'source': 'virustotal', 'error': True}
    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    return {
        'source': 'virustotal',
        'found': True,
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'harmless': stats.get('harmless', 0),
        'total_engines': sum(stats.values()),
        'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
    }


def _virustotal_hash(hash_val: str) -> Dict:
    if not VIRUSTOTAL_KEY:
        return {'source': 'virustotal', 'skipped': True}
    headers = {'x-apikey': VIRUSTOTAL_KEY}
    data = _get(f'https://www.virustotal.com/api/v3/files/{hash_val}', headers)
    if not data:
        return {'source': 'virustotal', 'error': True}
    attrs = data.get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    return {
        'source': 'virustotal',
        'found': True,
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'harmless': stats.get('harmless', 0),
        'total_engines': sum(stats.values()),
        'name': attrs.get('meaningful_name', 'Unknown'),
        'type': attrs.get('type_description', 'Unknown'),
        'size': attrs.get('size', 0),
        'first_submission': attrs.get('first_submission_date', ''),
        # FIX Bug 1: was returning raw dicts [{count, value}] instead of strings.
        # popular_threat_category is a list of {count, value} objects — extract 'value'.
        'malware_family': [
            item.get('value', '')
            for item in attrs.get('popular_threat_classification', {})
                              .get('popular_threat_category', [])[:3]
        ],
    }


def _virustotal_url(url: str) -> Dict:
    if not VIRUSTOTAL_KEY:
        return {'source': 'virustotal', 'skipped': True}
    headers = {'x-apikey': VIRUSTOTAL_KEY}
    # FIX: VirusTotal URL ID is base64url(url) with padding stripped — NOT sha256
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    data = _get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers)
    if not data:
        return {'source': 'virustotal', 'error': True}
    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    return {
        'source': 'virustotal',
        'found': True,
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'total_engines': sum(stats.values()),
    }


def _abuseipdb(ip: str) -> Dict:
    if not ABUSEIPDB_KEY:
        return {'source': 'abuseipdb', 'skipped': True}
    headers = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
    params  = {'ipAddress': ip, 'maxAgeInDays': 90}
    data = _get('https://api.abuseipdb.com/api/v2/check', headers, params)
    if not data:
        return {'source': 'abuseipdb', 'error': True}
    d = data.get('data', {})
    return {
        'source': 'abuseipdb',
        'found': True,
        'abuse_score': d.get('abuseConfidenceScore', 0),
        'total_reports': d.get('totalReports', 0),
        'last_reported': d.get('lastReportedAt', 'Never'),
        'usage_type': d.get('usageType', 'Unknown'),
        'isp': d.get('isp', 'Unknown'),
        'domain': d.get('domain', 'Unknown'),
        'is_whitelisted': d.get('isWhitelisted', False),
    }


def _hybrid_analysis_hash(hash_val: str) -> Dict:
    if not HYBRID_KEY:
        return {'source': 'hybrid_analysis', 'skipped': True}
    headers = {
        'api-key': HYBRID_KEY,
        'User-Agent': 'Falcon',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = _post(
        'https://hybrid-analysis.com/api/v2/search/hash',
        data={'hash': hash_val},
        headers=headers
    )
    if not data or not isinstance(data, list) or not data:
        return {'source': 'hybrid_analysis', 'found': False}
    top = data[0]
    return {
        'source': 'hybrid_analysis',
        'found': True,
        'verdict': top.get('verdict', 'Unknown'),
        'threat_score': top.get('threat_score', 0),
        'malware_family': top.get('vx_family', 'Unknown'),
        'file_type': top.get('type_short', 'Unknown'),
        'environment': top.get('environment_description', 'Unknown'),
        'analysis_start': top.get('analysis_start_time', 'Unknown'),
        'tags': top.get('tags', []),
    }


# ══════════════════════════════════════════════════════════════
# MAIN VALIDATOR
# ══════════════════════════════════════════════════════════════

def validate_ioc(iocs: Dict[str, List[str]]) -> Dict[str, Any]:
    """
    Validates all extracted IOCs against threat intel APIs in parallel.
    Returns structured validation results with confidence scoring.
    """
    if not iocs:
        return {}

    results: Dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}

        # IPv4 (public)
        for ip in iocs.get('ipv4', []):
            futures[executor.submit(_otx_ip, ip)]       = ('ipv4', ip, 'otx')
            futures[executor.submit(_greynoise, ip)]     = ('ipv4', ip, 'greynoise')
            futures[executor.submit(_ipapi, ip)]         = ('ipv4', ip, 'ipapi')
            futures[executor.submit(_virustotal_ip, ip)] = ('ipv4', ip, 'virustotal')
            futures[executor.submit(_abuseipdb, ip)]     = ('ipv4', ip, 'abuseipdb')
            futures[executor.submit(_threatfox, ip)]     = ('ipv4', ip, 'threatfox')

        # FIX Bug 2: ipv4_private from ioc_extractor was never processed — private
        # IPs disappeared from validation results entirely, so the analyzer had no
        # visibility into lateral movement / internal host indicators.
        # No external APIs for private IPs; add a stub result directly so they
        # appear in results with risk_level='private' for the analyzer to use.
        for ip in iocs.get('ipv4_private', []):
            key = f"ipv4_private:{ip}"
            results[key] = {
                'ioc_type':         'ipv4_private',
                'ioc_value':        ip,
                'sources':          {'internal': {'source': 'internal', 'note': 'Private/RFC-1918 address — no external intel available'}},
                'risk_level':       'private',
                'confidence_boost': 0,
                'verdict':          'Private',
                'source':           'Internal',
                'validated_at':     datetime.now(timezone.utc).isoformat(),
            }

        # Domains
        for domain in iocs.get('domain', []):
            futures[executor.submit(_otx_domain, domain)]    = ('domain', domain, 'otx')
            futures[executor.submit(_urlhaus_domain, domain)] = ('domain', domain, 'urlhaus')
            futures[executor.submit(_threatfox, domain)]     = ('domain', domain, 'threatfox')

        # URLs
        for url in iocs.get('url', []):
            futures[executor.submit(_urlhaus_url, url)]    = ('url', url, 'urlhaus')
            futures[executor.submit(_urlscan, url)]        = ('url', url, 'urlscan')
            futures[executor.submit(_virustotal_url, url)] = ('url', url, 'virustotal')
            futures[executor.submit(_threatfox, url)]      = ('url', url, 'threatfox')

        # Hashes
        for hash_type in ['md5', 'sha1', 'sha256']:
            for h in iocs.get(hash_type, []):
                futures[executor.submit(_malwarebazaar, h)]        = (hash_type, h, 'malwarebazaar')
                futures[executor.submit(_otx_hash, h)]             = (hash_type, h, 'otx')
                futures[executor.submit(_threatfox, h)]            = (hash_type, h, 'threatfox')
                futures[executor.submit(_virustotal_hash, h)]      = (hash_type, h, 'virustotal')
                futures[executor.submit(_hybrid_analysis_hash, h)] = (hash_type, h, 'hybrid_analysis')

        # Collect results
        # FIX Bug 3: as_completed(timeout=30) fires TimeoutError on the for-loop
        # itself (outside the inner try/except), so slow networks crashed the whole
        # validate_ioc call with an unhandled exception → HTTP 500.
        # Fix: wrap the entire iteration in a try/except TimeoutError.
        try:
            for future in as_completed(futures, timeout=30):
                ioc_type, ioc_value, source = futures[future]
                try:
                    result = future.result()
                    key = f"{ioc_type}:{ioc_value}"
                    if key not in results:
                        results[key] = {
                            'ioc_type':         ioc_type,
                            'ioc_value':        ioc_value,
                            'sources':          {},
                            'risk_level':       'unknown',
                            'confidence_boost': 0,
                        }
                    results[key]['sources'][source] = result
                except Exception as e:
                    logger.error(f"Future error {source}:{ioc_value}: {e}")
        except TimeoutError:
            logger.warning("validate_ioc: global 30s timeout reached — partial results returned")

    # ── Risk Scoring + verdict ─────────────────────────────────
    _VERDICT_MAP = {
        'critical': 'Malicious',
        'high':     'Malicious',
        'medium':   'Suspicious',
        'low':      'Low Risk',
        'clean':    'Clean',
        'unknown':  'Unknown',
    }

    for key, entry in results.items():
        risk, boost = _calculate_risk(entry)
        entry['risk_level']       = risk
        entry['confidence_boost'] = boost
        # FIX: add verdict field — frontend renderValidation() reads result.verdict
        entry['verdict']          = _VERDICT_MAP.get(risk, 'Unknown')
        entry['source']           = 'Multi-Source'
        entry['validated_at']     = datetime.now(timezone.utc).isoformat()

    return results


def _calculate_risk(entry: Dict) -> tuple:
    """Calculate risk level and confidence boost from all source results."""
    score   = 0
    sources = entry.get('sources', {})

    # VirusTotal — highest weight
    vt = sources.get('virustotal', {})
    if vt.get('malicious', 0) > 10:
        score += 30
    elif vt.get('malicious', 0) > 3:
        score += 20
    elif vt.get('malicious', 0) > 0:
        score += 10

    # AbuseIPDB
    abuse_score = sources.get('abuseipdb', {}).get('abuse_score', 0)
    if abuse_score > 80:
        score += 20
    elif abuse_score > 40:
        score += 12
    elif abuse_score > 10:
        score += 6

    # OTX
    if sources.get('otx', {}).get('found'):
        score += min(sources['otx'].get('pulse_count', 0) * 2, 15)

    # ThreatFox
    if sources.get('threatfox', {}).get('found'):
        score += 15

    # MalwareBazaar
    if sources.get('malwarebazaar', {}).get('found'):
        score += 15

    # GreyNoise
    gn = sources.get('greynoise', {})
    if gn.get('classification') == 'malicious':
        score += 15
    elif gn.get('noise') and not gn.get('riot'):
        score += 5

    # URLhaus
    if sources.get('urlhaus', {}).get('found'):
        score += 12

    # Hybrid Analysis
    ha = sources.get('hybrid_analysis', {})
    if ha.get('verdict') in ('malicious', 'suspicious'):
        score += 15

    # ip-api proxy/hosting intelligence (free, no key — always runs even when paid APIs fail)
    # TOR exit nodes and known proxies show is_proxy=True — this is a critical signal
    ipapi_d = sources.get('ipapi', {})
    if ipapi_d.get('is_proxy'):
        score += 70   # Confirmed TOR/anonymous proxy — definitive malicious signal (→ critical)
    elif ipapi_d.get('is_hosting'):
        score += 10   # Datacenter/VPS — elevated risk, often used for attacks

    score = min(score, 100)

    if score >= 70:
        return 'critical', 15
    elif score >= 45:
        return 'high', 10
    elif score >= 20:
        return 'medium', 5
    elif score > 0:
        return 'low', 2
    else:
        return 'clean', 0


def get_validation_summary(validation_results: Dict) -> Dict:
    """Returns high-level summary for confidence scoring in analyzer."""
    if not validation_results:
        return {
            'total': 0, 'malicious': 0,
            'suspicious': 0, 'clean': 0, 'total_boost': 0
        }

    summary = {
        'total':       len(validation_results),
        'malicious':   0,
        'suspicious':  0,
        'clean':       0,
        'total_boost': 0,
    }

    for entry in validation_results.values():
        risk = entry.get('risk_level', 'unknown')
        if risk in ('critical', 'high'):
            summary['malicious'] += 1
        elif risk == 'medium':
            summary['suspicious'] += 1
        else:
            summary['clean'] += 1
        summary['total_boost'] += entry.get('confidence_boost', 0)

    summary['total_boost'] = min(summary['total_boost'], 35)
    return summary
