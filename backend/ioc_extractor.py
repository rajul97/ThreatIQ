import re
from typing import Dict, List


# ── Regex Patterns ─────────────────────────────────────────────
PATTERNS = {
    'ipv4': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    'ipv6': re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
    ),
    'domain': re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}\b'
    ),
    'url': re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        r'(?:/(?:[-\w@!$&\'()*+,;=:~]|(?:%[\da-fA-F]{2}))*)*'
        r'(?:\?(?:[-\w@!$&\'()*+,;=:~/?]|(?:%[\da-fA-F]{2}))*)?'
    ),
    'md5':    re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1':   re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'email':  re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'),
    'cve':    re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
    'registry': re.compile(
        r'\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKCR)'
        r'(?:\\[\w\s\-\.]+)+\b'
    ),
    'file_path_windows': re.compile(
        r'\b[A-Za-z]:\\(?:[\w\s\-\.]+\\)*[\w\s\-\.]+(?:\.\w+)?\b'
    ),
    'file_path_linux': re.compile(
        r'\b(?:/(?:etc|tmp|var|usr|bin|sbin|home|root|opt|proc|sys)'
        r'(?:/[\w\s\-\.]+)*)\b'
    ),
    'event_id': re.compile(r'\bEventID[:\s]+(\d{3,5})\b', re.IGNORECASE),
    'mutex':    re.compile(r'\bMutex[:\s]+[\w\-\.]+\b', re.IGNORECASE),
    'user_agent': re.compile(
        r'User-Agent[:\s]+.+?(?=\n|$)', re.IGNORECASE
    ),
    # FIX Bug 2: trailing \b fails on base64 strings ending in '=' or '=='
    # because '=' is not a word character so \b never matches after it.
    # Standard base64 padding ends in '=' — almost all real payloads are missed.
    # Replace trailing \b with negative lookahead (?![A-Za-z0-9+/=]) instead.
    'base64': re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])'),
}

# IPs to ignore (private/loopback)
PRIVATE_IP_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^127\.'),
    re.compile(r'^0\.0\.0\.0$'),
    re.compile(r'^255\.255\.255\.255$'),
]

# Domains to ignore
COMMON_DOMAINS = {
    'google.com', 'microsoft.com', 'windows.com', 'apple.com',
    'github.com', 'cloudflare.com', 'amazonaws.com', 'localhost'
}

# FIX Bug 3: file extensions misidentified as TLDs (e.g. svchost.exe → domain)
# The domain regex allows any 2+ letter TLD — filter out known file extensions.
_FAKE_TLD_EXTENSIONS = {
    'exe', 'dll', 'bat', 'ps1', 'txt', 'log', 'csv', 'xml',
    'json', 'cfg', 'ini', 'sys', 'tmp', 'vbs', 'js', 'py',
    'sh', 'cmd', 'msi', 'cab', 'zip', 'rar', 'tar', 'gz',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'lnk', 'hta', 'jar', 'class', 'bin', 'iso', 'img',
}


def _is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_IP_RANGES)


def _is_common_domain(domain: str) -> bool:
    return domain.lower() in COMMON_DOMAINS


def _deduplicate(items: List[str]) -> List[str]:
    seen   = set()
    result = []
    for item in items:
        if item.lower() not in seen:
            seen.add(item.lower())
            result.append(item)
    return result


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract all IOCs from raw input text.
    Returns a dict with IOC types as keys and lists of found IOCs as values.
    """
    if not text:
        return {}

    results: Dict[str, List[str]] = {}

    # Extract URLs first (before domains to avoid overlap)
    urls = PATTERNS['url'].findall(text)
    if urls:
        results['url'] = _deduplicate(urls)

    # Remove URLs from text for domain extraction
    text_no_urls = PATTERNS['url'].sub('', text)

    # Extract IPs
    # FIX Bug 4: private IPs were silently dropped — a single private IP input
    # (e.g. "192.168.1.1") ended up with no 'ipv4' key, so classify_input_type
    # fell through to 'description' instead of 'ip'.
    # Fix: public IPs go into 'ipv4'; private IPs go into 'ipv4_private' so
    # they're still present for classification and validation purposes.
    all_ipv4s = PATTERNS['ipv4'].findall(text_no_urls)
    ipv4s         = [ip for ip in all_ipv4s if not _is_private_ip(ip)]
    ipv4s_private = [ip for ip in all_ipv4s if     _is_private_ip(ip)]
    if ipv4s:
        results['ipv4'] = _deduplicate(ipv4s)
    if ipv4s_private:
        results['ipv4_private'] = _deduplicate(ipv4s_private)

    ipv6s = PATTERNS['ipv6'].findall(text_no_urls)
    if ipv6s:
        results['ipv6'] = _deduplicate(ipv6s)

    # Extract domains (filter out already found IPs and common domains)
    found_ips = set(results.get('ipv4', []))
    domains = [
        d for d in PATTERNS['domain'].findall(text_no_urls)
        if d not in found_ips
        and not _is_common_domain(d)
        and d.rsplit('.', 1)[-1].lower() not in _FAKE_TLD_EXTENSIONS
    ]
    if domains:
        results['domain'] = _deduplicate(domains)

    # Extract hashes (order matters: sha256 > sha1 > md5 to prevent substring overlap)
    sha256s = PATTERNS['sha256'].findall(text)
    if sha256s:
        results['sha256'] = _deduplicate(sha256s)

    # Remove sha256 matches before sha1 extraction to avoid 40-char substrings
    text_no_sha256 = text
    for h in sha256s:
        text_no_sha256 = text_no_sha256.replace(h, '')

    sha1s = PATTERNS['sha1'].findall(text_no_sha256)
    if sha1s:
        results['sha1'] = _deduplicate(sha1s)

    text_no_hashes = text_no_sha256
    for h in sha1s:
        text_no_hashes = text_no_hashes.replace(h, '')

    md5s = PATTERNS['md5'].findall(text_no_hashes)
    if md5s:
        results['md5'] = _deduplicate(md5s)

    # FIX Bug 1: 'user_agent' was defined in PATTERNS but never extracted —
    # it was missing from this loop. Any User-Agent header in input was silently
    # ignored. Added 'user_agent' to the list below.
    for ioc_type in ['email', 'cve', 'registry', 'file_path_windows',
                     'file_path_linux', 'event_id', 'mutex', 'user_agent']:
        matches = PATTERNS[ioc_type].findall(text)
        if matches:
            results[ioc_type] = _deduplicate(list(matches))

    # Extract base64 (only suspicious looking ones, skip short/common)
    b64_matches = PATTERNS['base64'].findall(text)
    suspicious_b64 = [b for b in b64_matches if len(b) > 40]
    if suspicious_b64:
        results['base64_suspicious'] = _deduplicate(suspicious_b64)

    return results


def get_ioc_summary(iocs: Dict[str, List[str]]) -> Dict:
    """Returns a summary count of all extracted IOCs."""
    total = sum(len(v) for v in iocs.values())
    return {
        'total_iocs'  : total,
        'breakdown'   : {k: len(v) for k, v in iocs.items()},
        'has_hashes'  : any(k in iocs for k in ['md5', 'sha1', 'sha256']),
        'has_network' : any(k in iocs for k in ['ipv4', 'ipv6', 'domain', 'url']),
        'has_host'    : any(k in iocs for k in ['registry', 'file_path_windows',
                                                  'file_path_linux', 'event_id']),
    }


def classify_input_type(text: str, iocs: Dict[str, List[str]]) -> str:
    """Auto-detect what type of input was provided."""
    text_lower = text.lower()

    # FIX Bug 5: hash threshold was < 5 words — too strict.
    # "SHA256: <hash>" = 2 words, or a hash pasted with a short label fails.
    # Raised to < 10 so short descriptions + hash still classify correctly.
    if any(k in iocs for k in ['md5', 'sha1', 'sha256']) and len(text.split()) < 10:
        return 'hash'

    # FIX Bug 4 (continued): also check ipv4_private for 'ip' classification
    if any(k in iocs for k in ['ipv4', 'ipv4_private']) and len(text.split()) < 3:
        return 'ip'

    if 'url' in iocs and len(text.split()) < 3:
        return 'url'

    if 'domain' in iocs and len(text.split()) < 3:
        return 'domain'

    if any(kw in text_lower for kw in ['eventid', 'event id', 'logon', 'security',
                                        'system log', 'application log', 'syslog']):
        return 'log'

    if any(kw in text_lower for kw in ['dns', 'netflow', 'tcp', 'udp', 'http',
                                        'firewall', 'packet', 'traffic']):
        return 'network'

    if any(kw in text_lower for kw in ['powershell', 'cmd', 'process', 'executable',
                                        'payload', 'script', 'file']):
        return 'file'

    if any(kw in text_lower for kw in ['apt', 'malware', 'ransomware', 'attack',
                                        'campaign', 'threat', 'breach']):
        return 'description'

    return 'description'
