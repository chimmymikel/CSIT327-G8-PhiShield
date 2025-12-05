import re
import urllib.parse
import requests
import socket
import ssl
import logging
from datetime import datetime
from difflib import SequenceMatcher
import os

logger = logging.getLogger('phishield.analysis')

# Enhanced suspicious keywords list
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'bank', 
    'confirm', 'password', 'signin', 'suspended', 'locked',
    'urgent', 'immediate', 'action', 'click', 'prize', 'winner',
    'validate', 'authenticate', 'verify-account', 'update-info',
    'security-alert', 'account-locked', 'suspended-account'
]

# Well-known legitimate domains for typosquatting detection
# The system will detect typosquatting attempts for ALL domains in this list
LEGITIMATE_DOMAINS = [
    # Tech & Social Media
    'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'paypal.com', 'ebay.com', 'netflix.com',
    'twitter.com', 'instagram.com', 'linkedin.com', 'github.com',
    'yahoo.com', 'outlook.com', 'gmail.com', 'hotmail.com',
    # Banking & Financial
    'bankofamerica.com', 'wellsfargo.com', 'chase.com', 'citibank.com',
    'usbank.com', 'pnc.com', 'tdbank.com', 'capitalone.com',
    # Cloud & Services
    'amazonaws.com', 'microsoftonline.com', 'office365.com',
    'dropbox.com', 'onedrive.com', 'icloud.com',
    # Additional Popular Sites
    'reddit.com', 'pinterest.com', 'tiktok.com', 'snapchat.com',
    'whatsapp.com', 'telegram.org', 'discord.com', 'zoom.us',
    'adobe.com', 'spotify.com', 'uber.com', 'airbnb.com'
]

IP_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')

# Extended suspicious TLDs
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
    '.download', '.stream', '.review', '.science', '.accountant'
]

# URL shortening services (legitimate but can be abused)
SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'short.link', 'rebrand.ly', 'cutt.ly'
]


def check_phish_tank(url):
    """
    Check URL against PhishTank API
    Returns: (is_phishing, confidence) or (None, None) if API unavailable
    """
    try:
        phishtank_api_key = os.getenv('PHISHTANK_API_KEY', '')
        phishtank_url = 'http://checkurl.phishtank.com/checkurl/'
        
        # PhishTank API requires POST request
        payload = {
            'url': url,
            'format': 'json',
            'app_key': phishtank_api_key if phishtank_api_key else None
        }
        
        response = requests.post(
            phishtank_url,
            data=payload,
            timeout=5,
            headers={'User-Agent': 'PhiShield/1.0'}
        )
        
        if response.status_code == 200:
            data = response.json()
            if 'results' in data and 'in_database' in data['results']:
                if data['results']['in_database']:
                    verified = data['results'].get('verified', 'no')
                    return (True, 'verified' if verified == 'yes' else 'unverified')
        
        return (False, None)
    except requests.exceptions.RequestException as e:
        logger.debug(f"PhishTank API error: {str(e)}")
        return (None, None)
    except Exception as e:
        logger.debug(f"PhishTank check error: {str(e)}")
        return (None, None)


def check_google_safe_browsing(url):
    """
    Check URL against Google Safe Browsing API (Primary threat detection API)
    Detects: Social Engineering (Phishing), Malware, Unwanted Software
    
    Returns: (is_threat, threat_types) or (None, None) if API unavailable
    Get API key: https://console.cloud.google.com/apis/credentials
    Free tier: 10,000 requests/day
    """
    try:
        api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
        if not api_key:
            logger.debug("Google Safe Browsing API key not configured")
            return (None, None)
        
        api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
        
        payload = {
            'client': {
                'clientId': 'phishield',
                'clientVersion': '1.0'
            },
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if 'matches' in data and len(data['matches']) > 0:
                threat_types = [match.get('threatType', 'UNKNOWN') for match in data['matches']]
                return (True, threat_types)
        
        return (False, None)
    except requests.exceptions.RequestException as e:
        logger.debug(f"Google Safe Browsing API error: {str(e)}")
        return (None, None)
    except Exception as e:
        logger.debug(f"Safe Browsing check error: {str(e)}")
        return (None, None)


def check_domain_reputation(domain):
    """
    Check domain reputation indicators
    Returns: list of reputation flags
    """
    flags = []
    
    try:
        # Check if domain resolves
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            flags.append('Domain does not resolve (suspicious)')
            return flags
        
        # Check SSL certificate (if HTTPS)
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    # Check certificate validity
                    # Note: This is a basic check - full validation would require more code
        except Exception:
            flags.append('No valid SSL certificate detected')
        
        # Check for suspicious subdomain patterns
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            flags.append(f'Excessive subdomains ({subdomain_count} levels)')
        
        # Check for numeric subdomains (often suspicious)
        parts = domain.split('.')
        if len(parts) > 0 and parts[0].isdigit():
            flags.append('Numeric subdomain detected (suspicious)')
        
    except Exception as e:
        logger.debug(f"Domain reputation check error: {str(e)}")
    
    return flags


def detect_typosquatting(domain):
    """
    Detect typosquatting by comparing domain to known legitimate domains
    Returns: (is_typosquatting, similar_domain, similarity_score)
    """
    domain_lower = domain.lower()
    
    # First check: If the domain exactly matches a legitimate domain, it's not typosquatting
    # Also check if it's a subdomain of a legitimate domain (e.g., gemini.google.com is legitimate)
    # Normalize domain (remove www. prefix if present)
    normalized_domain = domain_lower
    if normalized_domain.startswith('www.'):
        normalized_domain = normalized_domain[4:]
    
    # Check exact match and subdomain match against legitimate domains
    for legit_domain in LEGITIMATE_DOMAINS:
        legit_normalized = legit_domain.lower()
        if legit_normalized.startswith('www.'):
            legit_normalized = legit_normalized[4:]
        
        # Exact match means it's the legitimate domain itself, not typosquatting
        if normalized_domain == legit_normalized:
            return (False, None, 0)
        
        # Check if the domain is a subdomain of a legitimate domain
        # e.g., gemini.google.com ends with .google.com, so it's legitimate
        if normalized_domain.endswith('.' + legit_normalized):
            return (False, None, 0)
    
    # Remove TLD for comparison
    domain_parts = domain_lower.split('.')
    if len(domain_parts) < 2:
        return (False, None, 0)
    
    # Get the main domain name (last two parts: example.com -> example)
    # Handle cases like www.example.com -> example
    if len(domain_parts) >= 2:
        if domain_parts[0] == 'www' and len(domain_parts) >= 3:
            domain_name = domain_parts[1]  # www.example.com -> example
        else:
            domain_name = domain_parts[-2]  # example.com -> example
    else:
        domain_name = domain_parts[0]
    
    best_match = None
    best_score = 0
    
    # Common character substitution patterns (typosquatting)
    char_subs = {
        '0': 'o', 'o': '0',
        '1': 'i', 'i': '1', 'l': '1', '1': 'l',
        '3': 'e', 'e': '3',
        '4': 'a', 'a': '4',
        '5': 's', 's': '5',
        '7': 't', 't': '7',
        '@': 'a', 'a': '@'
    }
    
    for legit_domain in LEGITIMATE_DOMAINS:
        legit_parts = legit_domain.split('.')
        if len(legit_parts) < 2:
            continue
        
        # Get main domain name
        if legit_parts[0] == 'www' and len(legit_parts) >= 3:
            legit_name = legit_parts[1]
        else:
            legit_name = legit_parts[-2]
        
        # Calculate base similarity
        similarity = SequenceMatcher(None, domain_name, legit_name).ratio()
        
        # Enhanced check for character substitutions (0/o, 1/i/l, etc.)
        if len(domain_name) == len(legit_name):
            # Check for number/letter substitutions
            has_char_sub = False
            diff_count = 0
            
            for i, (d_char, l_char) in enumerate(zip(domain_name, legit_name)):
                if d_char != l_char:
                    diff_count += 1
                    # Check if it's a common typosquatting substitution
                    if (d_char in char_subs and char_subs[d_char] == l_char) or \
                       (l_char in char_subs and char_subs[l_char] == d_char):
                        has_char_sub = True
            
            # If 1-2 differences and at least one is a char substitution, flag it
            if diff_count <= 2 and diff_count > 0 and has_char_sub:
                # Boost similarity score for character substitutions
                similarity = max(similarity, 0.85)
                if similarity > best_score:
                    best_score = similarity
                    best_match = legit_domain
        
        # Check for character substitutions, additions, deletions
        if similarity > 0.65 and similarity < 1.0:  # Lowered threshold from 0.7
            if similarity > best_score:
                best_score = similarity
                best_match = legit_domain
        
        # Check for missing/extra characters (e.g., googl.com, googles.com)
        length_diff = abs(len(domain_name) - len(legit_name))
        if length_diff <= 1 and similarity > 0.75:  # Lowered from 0.8
            if similarity > best_score:
                best_score = similarity
                best_match = legit_domain
    
    # Lowered threshold for typosquatting detection (from 0.75 to 0.70)
    if best_score > 0.70 and best_match:
        return (True, best_match, best_score)
    
    return (False, None, 0)


def check_url_shortening(url, domain):
    """
    Check if URL uses shortening service
    Returns: (is_shortened, service_name)
    """
    for service in SHORTENING_SERVICES:
        if service in domain.lower():
            return (True, service)
    return (False, None)


def analyze_url(url):
    """
    Enhanced URL analysis with multiple detection methods
    """
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        flagged = []
        risk_score = 0
        
        domain_only = domain.split(':')[0]
        
        # ========== BASIC CHECKS (Tuned) ==========
        
        # IP address check (high risk)
        if IP_RE.match(domain_only):
            flagged.append('Domain is an IP address (highly suspicious)')
            risk_score += 30
        
        # Suspicious keywords (tuned - only flag if in domain or path)
        url_lower = url.lower()
        found_keywords = []
        for keyword in SUSPICIOUS_KEYWORDS:
            # Check if keyword is in domain or path (not just anywhere in URL)
            if keyword in domain_only or keyword in parsed.path.lower():
                found_keywords.append(keyword)
                risk_score += 2
        
        if found_keywords:
            flagged.append(f'Contains suspicious keywords: {", ".join(found_keywords[:5])}')
        
        # Hyphen count (tuned threshold)
        hyphen_count = domain_only.count('-')
        if hyphen_count > 3:  # Increased threshold from 2 to 3
            flagged.append(f'Domain has many hyphens ({hyphen_count}) - potential spoofing')
            risk_score += 5
        
        # Suspicious TLDs (enhanced list)
        for tld in SUSPICIOUS_TLDS:
            if domain_only.endswith(tld):
                flagged.append(f'Suspicious top-level domain: {tld}')
                risk_score += 8
                break
        
        # URL obfuscation checks
        if '@' in url:
            flagged.append('Contains @ symbol (URL obfuscation technique)')
            risk_score += 15
        
        # Long URL check (tuned threshold)
        if len(url) > 150:  # Reduced from 200 to 150
            flagged.append(f'Extremely long URL ({len(url)} chars) - potential obfuscation')
            risk_score += 5
        
        # ========== NEW: TYPOSQUATTING DETECTION ==========
        is_typosquatting, similar_domain, similarity = detect_typosquatting(domain_only)
        if is_typosquatting:
            flagged.append(f'Possible typosquatting detected (similar to {similar_domain}, {similarity:.0%} match)')
            risk_score += 25
        
        # ========== NEW: URL SHORTENING CHECK ==========
        is_shortened, service = check_url_shortening(url, domain_only)
        if is_shortened:
            flagged.append(f'Uses URL shortening service ({service}) - verify destination')
            risk_score += 3
        
        # ========== NEW: DOMAIN REPUTATION CHECKS ==========
        reputation_flags = check_domain_reputation(domain_only)
        flagged.extend(reputation_flags)
        risk_score += len(reputation_flags) * 5
        
        # ========== PRIMARY: GOOGLE SAFE BROWSING API CHECK ==========
        # This is the main threat detection API - highly recommended to configure
        safe_browsing_result, threat_types = check_google_safe_browsing(url)
        if safe_browsing_result is True:
            threat_str = ', '.join(threat_types) if threat_types else 'UNKNOWN'
            flagged.append(f'⚠️ BLOCKED BY GOOGLE SAFE BROWSING ({threat_str})')
            risk_score += 50
        elif safe_browsing_result is False:
            # Not flagged by Google (good sign)
            pass
        
        # ========== OPTIONAL: PHISHTANK API CHECK ==========
        # Secondary verification (optional - PhishTank registration currently disabled)
        phishtank_result, phishtank_confidence = check_phish_tank(url)
        if phishtank_result is True:
            if phishtank_confidence == 'verified':
                flagged.append('⚠️ CONFIRMED PHISHING SITE (PhishTank verified)')
                risk_score += 50
            else:
                flagged.append('⚠️ Reported as phishing (PhishTank - unverified)')
                risk_score += 30
        elif phishtank_result is False:
            # Not in PhishTank database (good sign, but doesn't mean safe)
            pass
        
        # ========== ADDITIONAL ENHANCED CHECKS ==========
        
        # Check for port numbers (often suspicious)
        if ':' in domain and not domain.endswith(':80') and not domain.endswith(':443'):
            port = domain.split(':')[-1]
            if port.isdigit() and port not in ['80', '443', '8080']:
                flagged.append(f'Non-standard port detected ({port})')
                risk_score += 5
        
        # Check for excessive path depth (potential obfuscation)
        path_depth = parsed.path.count('/')
        if path_depth > 5:
            flagged.append(f'Excessive path depth ({path_depth} levels)')
            risk_score += 3
        
        # Check for encoded characters (potential obfuscation)
        if '%' in url and url.count('%') > 3:
            flagged.append('Multiple URL-encoded characters detected')
            risk_score += 5
        
        # Check for mixed case in domain (potential spoofing)
        if domain != domain.lower() and domain != domain.upper():
            flagged.append('Mixed case domain (potential spoofing)')
            risk_score += 3
        
        # ========== RISK LEVEL DETERMINATION ==========
        
        # Determine final risk level based on score and critical flags
        has_critical_flag = any('CONFIRMED' in flag or 'BLOCKED' in flag for flag in flagged)
        has_high_risk_keyword = any(kw in url_lower for kw in ['password', 'login', 'bank', 'signin', 'verify-account'])
        
        if has_critical_flag or risk_score >= 50:
            result = 'dangerous'
        elif IP_RE.match(domain_only) or has_high_risk_keyword or risk_score >= 25:
            result = 'dangerous'
        elif risk_score >= 10 or len(flagged) >= 3:
            result = 'suspicious'
        elif risk_score > 0 or flagged:
            result = 'suspicious'
        else:
            result = 'safe'
        
        # Format flags for display
        flags_display = ' | '.join(flagged) if flagged else 'No threats detected'
        
        return result, flags_display
        
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return 'error', f'Error analyzing URL: {str(e)}'


def analyze_message(text):
    """Analyze text message for phishing indicators"""
    try:
        flagged = []
        
        found = [k for k in SUSPICIOUS_KEYWORDS if k in text.lower()]
        if found:
            flagged.append(f'Suspicious words: {", ".join(found[:3])}')

        urls = re.findall(r'https?://\S+', text)
        if len(urls) >= 2:
            flagged.append(f'Contains {len(urls)} links (suspicious)')
        elif len(urls) == 1:
            flagged.append('Contains a link')

        urgent_phrases = ['act now', 'urgent', 'verify your account', 'click here', 
                         'immediate action', 'suspended', 'expire', 'limited time']
        found_urgent = [p for p in urgent_phrases if p in text.lower()]
        if found_urgent:
            flagged.append(f'Urgent language detected: {", ".join(found_urgent[:2])}')

        personal_info = ['social security', 'ssn', 'credit card', 'cvv', 
                        'pin', 'date of birth', 'mother\'s maiden']
        found_personal = [p for p in personal_info if p in text.lower()]
        if found_personal:
            flagged.append('Requests personal information (HIGH RISK)')

        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if caps_ratio > 0.3 and len(text) > 20:
            flagged.append('Excessive capitalization detected')

        if not flagged:
            result = 'safe'
        elif found_personal or len(urls) > 1 or any(kw in text.lower() for kw in ['password', 'bank account', 'ssn']):
            result = 'dangerous'
        elif flagged:
            result = 'suspicious'
        else:
            result = 'safe'

        return result, ' | '.join(flagged) if flagged else 'No threats detected'

    except Exception as e:
        return 'error', f'Error analyzing message: {str(e)}'
