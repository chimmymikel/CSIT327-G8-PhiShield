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
    """
    Enhanced message analysis with comprehensive phishing detection
    Analyzes text for multiple phishing indicators including URLs, patterns, and emotional manipulation
    """
    try:
        flagged = []
        risk_score = 0
        text_lower = text.lower()
        text_length = len(text)
        
        # ========== URL DETECTION AND ANALYSIS ==========
        # Enhanced URL pattern matching (more precise to avoid false positives)
        # Only match actual URLs, not domain names in regular text
        url_patterns = [
            r'https?://[^\s<>"\'\)]+',  # Standard URLs with protocol
            r'www\.[^\s<>"\'\)]+',      # www URLs without protocol (must be at word boundary)
        ]
        
        all_urls = []
        for pattern in url_patterns:
            found_urls = re.findall(pattern, text, re.IGNORECASE)
            all_urls.extend(found_urls)
        
        # Remove duplicates and clean URLs
        unique_urls = []
        for url in all_urls:
            # Clean up URLs (remove trailing punctuation)
            url = url.rstrip('.,;:!?)')
            # Only add if it looks like a real URL (has domain structure)
            if '.' in url and len(url) > 4 and url not in unique_urls:
                unique_urls.append(url)
        
        # Analyze each URL found in the message
        url_risk_scores = []
        dangerous_urls = []
        suspicious_urls = []
        
        for url in unique_urls:
            # Normalize URL for analysis
            normalized_url = url
            if not url.startswith(('http://', 'https://')):
                normalized_url = 'https://' + url
            
            # Analyze the URL using the same function as link checker
            url_risk, url_flags = analyze_url(normalized_url)
            url_risk_scores.append(url_risk)
            
            if url_risk == 'dangerous':
                dangerous_urls.append(url)
                risk_score += 40
            elif url_risk == 'suspicious':
                suspicious_urls.append(url)
                risk_score += 15
            elif url_risk == 'safe':
                risk_score -= 2  # Slight positive indicator
        
        # Report URL findings (only flag if URLs are actually suspicious)
        if dangerous_urls:
            flagged.append(f'⚠️ DANGEROUS URL(s) detected: {len(dangerous_urls)} malicious link(s) found')
        if suspicious_urls:
            flagged.append(f'⚠️ Suspicious URL(s) detected: {len(suspicious_urls)} questionable link(s) found')
        # Only flag multiple URLs if they're suspicious - legitimate emails often have 2-3 links
        if len(unique_urls) >= 4:  # Increased threshold from 3 to 4
            flagged.append(f'Multiple URLs detected ({len(unique_urls)}) - verify all destinations')
            risk_score += 8  # Reduced from 10
        elif len(unique_urls) == 3 and (dangerous_urls or suspicious_urls):
            flagged.append(f'Three URLs detected with suspicious links - verify destinations')
            risk_score += 5
        # Don't flag single safe URLs - too many false positives
        # Only flag if URL is suspicious or combined with other red flags
        
        # ========== URGENCY AND PRESSURE TACTICS ==========
        # More specific phrases - "action required" is too common in legitimate emails
        # Check this FIRST as it's used in keyword detection logic
        urgent_phrases = [
            r'\bact\s+now\b', r'\burgent.*action\b', r'\bimmediate\s+action\s+required\b',
            r'\bverify\s+your\s+account\s+immediately\b', r'\bclick\s+here\s+now\b',
            r'\baccount\s+will\s+be\s+suspended\b', r'\bexpires\s+today\b',
            r'\bwithin\s+24\s+hours\b', r'\bwithin\s+48\s+hours\b', r'\btoday\s+only\b',
            r'\blast\s+chance\b', r'\byour\s+account\s+will\s+be\s+closed\b',
            r'\byour\s+account\s+will\s+be\s+deleted\b', r'\bverify\s+now\s+or\s+lose\s+access\b',
            r'\brespond\s+immediately\b', r'\bright\s+away\b', r'\bwithout\s+delay\b'
        ]
        
        found_urgent = [p for p in urgent_phrases if re.search(p, text_lower)]
        # Only flag urgency if combined with other suspicious elements or very strong phrases
        urgency_flagged = False
        if found_urgent:
            # Check for very strong urgency phrases
            strong_urgency = any(re.search(p, text_lower) for p in [
                r'\baccount\s+will\s+be\s+(closed|deleted|suspended)\b',
                r'\bverify\s+now\s+or\s+lose\s+access\b',
                r'\bexpires\s+today\b', r'\bwithin\s+24\s+hours\b'
            ])
            if strong_urgency or len(unique_urls) > 0:
                flagged.append(f'⏰ Urgency tactics detected')
                risk_score += 18  # Reduced from 20
                urgency_flagged = True
        
        # ========== ENHANCED KEYWORD DETECTION ==========
        # Use word boundaries to avoid false matches (e.g., "accounting" shouldn't match "account")
        high_risk_keywords = [
            r'\bpassword\b', r'\bssn\b', r'\bsocial\s+security\b', r'\bcredit\s+card\b', 
            r'\bcvv\b', r'\bpin\s+number\b', r'\bbank\s+account\b', r'\brouting\s+number\b', 
            r'\baccount\s+number\b', r'\bmother\'?s?\s+maiden\b', r'\bdate\s+of\s+birth\b',
            r'\bdriver\s+license\b', r'\bpassport\s+number\b'
        ]
        
        medium_risk_keywords = [
            r'\bverify\s+your\s+account\b', r'\bconfirm\s+your\s+account\b', 
            r'\bvalidate\s+your\s+account\b', r'\bauthenticate\s+your\s+account\b',
            r'\baccount\s+suspended\b', r'\baccount\s+locked\b', r'\baccount\s+expired\b',
            r'\bsecurity\s+alert\b', r'\bunauthorized\s+access\b', r'\baccount\s+closure\b',
            r'\bimmediate\s+action\s+required\b'
        ]
        
        low_risk_keywords = [
            r'\bprize\b', r'\bwinner\b', r'\bcongratulations.*won\b', r'\bclaim\s+your\s+prize\b',
            r'\blimited\s+time\s+offer\b', r'\bact\s+now\b'
        ]
        
        found_high_risk = [kw for kw in high_risk_keywords if re.search(kw, text_lower)]
        found_medium_risk = [kw for kw in medium_risk_keywords if re.search(kw, text_lower)]
        found_low_risk = [kw for kw in low_risk_keywords if re.search(kw, text_lower)]
        
        # Only flag if keywords appear in suspicious context
        if found_high_risk:
            flagged.append(f'🚨 HIGH RISK: Requests sensitive information')
            risk_score += 35
        # Medium risk keywords are common in legitimate emails - only flag if combined with other red flags
        if found_medium_risk and (len(unique_urls) > 0 or urgency_flagged or risk_score > 10):
            flagged.append(f'⚠️ Account security keywords detected')
            risk_score += 12  # Reduced from 15
        # Low risk keywords only matter if combined with other suspicious elements
        if found_low_risk and (found_high_risk or len(unique_urls) > 0 or urgency_flagged):
            flagged.append(f'Suspicious promotional language detected')
            risk_score += 5
        
        # ========== EMOTIONAL MANIPULATION ==========
        fear_phrases = [
            'your account has been compromised', 'unauthorized access detected',
            'security breach', 'fraudulent activity', 'suspicious activity',
            'your account will be closed', 'legal action', 'account termination',
            'immediate suspension', 'violation detected'
        ]
        
        greed_phrases = [
            'you have won', 'congratulations', 'prize', 'reward', 'free money',
            'claim your prize', 'you are selected', 'exclusive offer', 'limited offer',
            'special promotion', 'claim now', 'free gift'
        ]
        
        found_fear = [p for p in fear_phrases if p in text_lower]
        found_greed = [p for p in greed_phrases if p in text_lower]
        
        if found_fear:
            flagged.append(f'😨 Fear-based manipulation detected: {", ".join(found_fear[:2])}')
            risk_score += 18
        if found_greed:
            flagged.append(f'💰 Greed-based manipulation detected: {", ".join(found_greed[:2])}')
            risk_score += 12
        
        # ========== GRAMMAR AND SPELLING ANALYSIS ==========
        # Common phishing email errors - only flag if multiple errors
        common_errors = [
            r'\b(youre|ur)\s+(account|email|password)\b',  # Your/you're errors (not "your" which is correct)
            r'\bclick\s+hear\b',  # Common typo (not "click here" which is correct)
            r'\b(recieve|recieved)\b',  # Receive misspellings
            r'\b(seperate|seperated)\b',  # Separate misspellings
            r'\b(acount|accont)\b',  # Account misspellings
        ]
        
        error_count = 0
        for pattern in common_errors:
            if re.search(pattern, text_lower):
                error_count += 1
        
        # Only flag if 3+ errors - one typo is normal, two might be coincidence
        if error_count >= 3:
            flagged.append(f'Multiple grammar/spelling errors detected ({error_count}) - common in phishing')
            risk_score += 8
        elif error_count >= 2 and (len(unique_urls) > 0 or found_high_risk):
            # Only flag 2 errors if combined with other suspicious elements
            flagged.append(f'Grammar/spelling errors detected ({error_count})')
            risk_score += 5
        
        # ========== FORMATTING ANALYSIS ==========
        # Excessive capitalization - be more lenient
        caps_ratio = sum(1 for c in text if c.isupper()) / max(text_length, 1)
        # Check if it's ALL CAPS (screaming) vs just headers
        all_caps_words = sum(1 for word in text.split() if word.isupper() and len(word) > 2)
        total_words = len(text.split())
        all_caps_ratio = all_caps_words / max(total_words, 1) if total_words > 0 else 0
        
        if all_caps_ratio > 0.5 and text_length > 50:  # More than half words are all caps
            flagged.append('Excessive ALL CAPS text - common phishing tactic')
            risk_score += 10
        elif caps_ratio > 0.5 and text_length > 30:  # More than 50% of characters are caps
            flagged.append('High capitalization ratio detected')
            risk_score += 5
        
        # Excessive exclamation marks - be more lenient (3 is normal in some contexts)
        exclamation_count = text.count('!')
        if exclamation_count >= 6:  # Increased threshold from 5
            flagged.append(f'Excessive exclamation marks ({exclamation_count}) - urgency manipulation')
            risk_score += 8
        elif exclamation_count >= 4 and (found_urgent or len(unique_urls) > 0):
            # Only flag 4-5 if combined with other suspicious elements
            flagged.append(f'Multiple exclamation marks ({exclamation_count})')
            risk_score += 4
        
        # ========== SENDER ANALYSIS ==========
        # Check for email-like patterns in the message
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        
        if emails:
            # Check for suspicious sender patterns
            suspicious_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
            for email in emails:
                domain = email.split('@')[1].lower() if '@' in email else ''
                # If message claims to be from a company but sender is free email
                if any(company_kw in text_lower for company_kw in ['bank', 'paypal', 'amazon', 'microsoft', 'apple']) and \
                   any(susp_dom in domain for susp_dom in suspicious_domains):
                    flagged.append(f'⚠️ Suspicious sender: Claims to be from company but uses free email ({email})')
                    risk_score += 25
        
        # ========== PERSONAL INFORMATION REQUESTS ==========
        # Focus on truly sensitive info - "full name" and "phone number" are often requested legitimately
        sensitive_info_patterns = [
            r'\bsocial\s+security\b', r'\bssn\b', r'\bcredit\s+card\b', r'\bcvv\b', r'\bcvc\b',
            r'\bpin\s+number\b', r'\bdate\s+of\s+birth\b', r'\bmother\'?s?\s+maiden\b',
            r'\bbank\s+account\s+number\b', r'\brouting\s+number\b', r'\baccount\s+number\b',
            r'\bdriver\s+license\s+number\b', r'\bpassport\s+number\b'
        ]
        
        # Less sensitive but still notable
        moderate_info_patterns = [
            r'\bfull\s+name\b', r'\bhome\s+address\b', r'\bphone\s+number\b'
        ]
        
        sensitive_count = sum(1 for pattern in sensitive_info_patterns if re.search(pattern, text_lower))
        moderate_count = sum(1 for pattern in moderate_info_patterns if re.search(pattern, text_lower))
        
        # Only flag if requesting truly sensitive info
        if sensitive_count >= 2:
            flagged.append(f'🚨 Requests multiple types of sensitive information ({sensitive_count} types)')
            risk_score += 40
        elif sensitive_count == 1:
            flagged.append('⚠️ Requests sensitive personal information (HIGH RISK)')
            risk_score += 25
        elif sensitive_count == 1 and moderate_count >= 2:
            # One sensitive + multiple moderate = suspicious
            flagged.append('⚠️ Requests personal information')
            risk_score += 20
        
        # ========== LINK DISGUISING TECHNIQUES ==========
        # "Click here" is very common in legitimate emails - only flag if combined with other red flags
        if re.search(r'\bclick\s+(here|this|link|button)\b', text_lower) and len(unique_urls) > 0:
            # Only flag if URL is suspicious or combined with other red flags
            if dangerous_urls or suspicious_urls or found_high_risk or found_urgent:
                flagged.append('Uses generic link text with suspicious content - verify destination')
                risk_score += 5
        
        # HTML links are normal in emails - only flag if suspicious
        if re.search(r'<a\s+href', text_lower, re.IGNORECASE) and (dangerous_urls or suspicious_urls):
            flagged.append('HTML link tags with suspicious URLs detected')
            risk_score += 8
        
        # ========== MESSAGE LENGTH AND STRUCTURE ==========
        # Very short messages are often suspicious, but legitimate notifications can be short
        if text_length < 30 and len(unique_urls) > 0 and (dangerous_urls or suspicious_urls):
            flagged.append('Very short message with suspicious link - common phishing pattern')
            risk_score += 5
        
        # Very long messages with many links - only if truly excessive
        if text_length > 3000 and len(unique_urls) >= 4:
            flagged.append('Very long message with many links - potential obfuscation')
            risk_score += 5
        
        # ========== POSITIVE INDICATORS (reduce false positives) ==========
        # Check for professional formatting that suggests legitimate email
        positive_indicators = 0
        
        # Professional greeting
        if re.search(r'\b(dear|hello|hi|greetings)\s+', text_lower):
            positive_indicators += 1
        
        # Professional closing
        if re.search(r'\b(sincerely|regards|best|thank you|thanks)\b', text_lower):
            positive_indicators += 1
        
        # Contact information provided
        if re.search(r'\b(contact|phone|email|support|help)\b', text_lower) and len(text) > 100:
            positive_indicators += 1
        
        # Well-structured message (has paragraphs, proper spacing)
        if text.count('\n\n') >= 2 or (text.count('\n') >= 3 and text_length > 200):
            positive_indicators += 1
        
        # Reduce risk score if message appears professional
        if positive_indicators >= 3:
            risk_score = max(0, risk_score - 10)  # Reduce score for professional messages
        elif positive_indicators >= 2:
            risk_score = max(0, risk_score - 5)
        
        # ========== FINAL RISK ASSESSMENT ==========
        # Determine risk level based on comprehensive scoring
        has_critical_url = any(url_risk == 'dangerous' for url_risk in url_risk_scores)
        has_high_risk_keyword = len(found_high_risk) > 0
        has_personal_info_request = sensitive_count > 0
        has_multiple_red_flags = len(flagged) >= 5
        
        # Adjusted thresholds to reduce false positives
        if has_critical_url or risk_score >= 70 or (has_high_risk_keyword and has_personal_info_request):
            result = 'dangerous'
        elif risk_score >= 35 or (has_personal_info_request and len(unique_urls) > 0) or len(dangerous_urls) > 0:
            result = 'dangerous'
        elif risk_score >= 18 or (len(flagged) >= 4 and len(unique_urls) > 0) or len(suspicious_urls) > 0:
            result = 'suspicious'
        elif risk_score >= 8 or (len(flagged) >= 2 and len(unique_urls) > 0):
            result = 'suspicious'
        elif risk_score > 0 or len(flagged) > 0:
            result = 'suspicious'
        else:
            result = 'safe'
        
        # Format flags for display with better organization
        if flagged:
            # Group flags by severity
            critical_flags = [f for f in flagged if '🚨' in f or '⚠️' in f or 'DANGEROUS' in f.upper()]
            warning_flags = [f for f in flagged if f not in critical_flags]
            
            flags_display = ' | '.join(critical_flags + warning_flags)
        else:
            flags_display = 'No threats detected - message appears safe'
        
        return result, flags_display
        
    except Exception as e:
        logger.error(f"Error analyzing message: {str(e)}")
        return 'error', f'Error analyzing message: {str(e)}'
