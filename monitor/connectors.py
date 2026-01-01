import os
import requests
import feedparser
import time
from typing import Dict, List, Optional, Any

# Rate limiting
_last_request_time = {}
_min_request_interval = 1.0  # 1 second between requests per API


def _rate_limit(api_name: str):
    """Simple rate limiting"""
    current_time = time.time()
    if api_name in _last_request_time:
        elapsed = current_time - _last_request_time[api_name]
        if elapsed < _min_request_interval:
            time.sleep(_min_request_interval - elapsed)
    _last_request_time[api_name] = time.time()


def get_enrichment_data(ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
    """
    Main router function for enrichment data.
    
    Args:
        ioc_value: The IOC value (e.g., "1.2.3.4", "example.com", "abc123...")
        ioc_type: Type of IOC ("ip", "domain", "hash", "keyword")
    
    Returns:
        Dictionary with enrichment data or None on failure
    """
    if ioc_type == 'ip':
        report = _get_vt_report(f"ip-addresses/{ioc_value}")
        comments = _get_vt_comments(f"ip-addresses/{ioc_value}/comments")
        urlscan_report = _get_urlscan_report(ioc_value, ioc_type)
        neiki_report = _get_neiki_report(ioc_value, ioc_type)
        return {
            "virustotal": report,
            "virustotal_comments": comments,
            "urlscan": urlscan_report,
            "neiki": neiki_report
        }
    
    elif ioc_type == 'domain':
        report = _get_vt_report(f"domains/{ioc_value}")
        comments = _get_vt_comments(f"domains/{ioc_value}/comments")
        urlscan_report = _get_urlscan_report(ioc_value, ioc_type)
        neiki_report = _get_neiki_report(ioc_value, ioc_type)
        return {
            "virustotal": report,
            "virustotal_comments": comments,
            "urlscan": urlscan_report,
            "neiki": neiki_report
        }
    
    elif ioc_type == 'hash':
        vt_data = _get_vt_report(f"files/{ioc_value}")
        vt_comments = _get_vt_comments(f"files/{ioc_value}/comments")
        mb_data = _get_mb_report(ioc_value)
        neiki_report = _get_neiki_report(ioc_value, ioc_type)
        return {
            "virustotal": vt_data,
            "virustotal_comments": vt_comments,
            "malwarebazaar": mb_data,
            "neiki": neiki_report
        }
    
    elif ioc_type == 'keyword':
        return {"rss": _get_rss_updates(ioc_value)}
    
    else:
        return None


def _get_vt_comments(vt_comments_path: str) -> Optional[Dict[str, Any]]:
    """
    Get VirusTotal comments for a given API path.
    
    Args:
        vt_comments_path: API path for comments (e.g., "ip-addresses/1.2.3.4/comments")
    
    Returns:
        Full JSON response or None on failure
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    
    _rate_limit("virustotal")
    
    url = f"https://www.virustotal.com/api/v3/{vt_comments_path}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            # 404 is a "not found" which is not a critical error, so we don't log it
            pass
        else:
            print(f"VirusTotal comments API error: {e.response.status_code} - {e.response.text}", flush=True)
        return None
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal comments request error: {str(e)}", flush=True)
        return None


def _get_vt_report(vt_api_path: str) -> Optional[Dict[str, Any]]:
    """
    Get VirusTotal report for a given API path.
    
    Args:
        vt_api_path: API path (e.g., "ip-addresses/1.2.3.4")
    
    Returns:
        Full JSON response or None on failure
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("Warning: VIRUSTOTAL_API_KEY not set", flush=True)
        return None
    
    _rate_limit("virustotal")
    
    url = f"https://www.virustotal.com/api/v3/{vt_api_path}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"VirusTotal API error: {e.response.status_code} - {e.response.text}", flush=True)
        return None
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal request error: {str(e)}", flush=True)
        return None


def _get_mb_report(hash_value: str) -> Optional[Dict[str, Any]]:
    """
    Get MalwareBazaar report for a hash.
    
    Args:
        hash_value: The hash value to look up
    
    Returns:
        Full JSON response or None on failure
    """
    api_key = os.getenv("MALWAREBAZAAR_API_KEY")
    # Note: MalwareBazaar API doesn't always require API key, but we'll use it if provided
    
    _rate_limit("malwarebazaar")
    
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_info",
        "hash": hash_value
    }
    
    headers = {}
    if api_key:
        headers["Auth-Key"] = api_key
    
    try:
        response = requests.post(url, data=data, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"MalwareBazaar API error: {e.response.status_code} - {e.response.text}", flush=True)
        return None
    except requests.exceptions.RequestException as e:
        print(f"MalwareBazaar request error: {str(e)}", flush=True)
        return None


def _get_urlscan_report(ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
    """
    Get urlscan.io report for a domain or IP.
    
    Args:
        ioc_value: The IOC value (domain or IP)
        ioc_type: Type of IOC ("ip" or "domain")
    
    Returns:
        Full JSON response or None on failure
    """
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        return None
    
    _rate_limit("urlscan")
    
    url = "https://urlscan.io/api/v1/search/"
    params = {"q": f"{ioc_type}:{ioc_value}"}
    headers = {"API-Key": api_key}
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"urlscan.io API error: {e.response.status_code} - {e.response.text}", flush=True)
        return None
    except requests.exceptions.RequestException as e:
        print(f"urlscan.io request error: {str(e)}", flush=True)
        return None


def _get_neiki_report(ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
    """
    Get Neiki TIP report for an IOC.
    
    Args:
        ioc_value: The IOC value
        ioc_type: Type of IOC ("ip", "domain", "hash")
    
    Returns:
        Full JSON response or None on failure
    """
    api_key = os.getenv("NEIKI_API_KEY")
    if not api_key:
        return None
    
    _rate_limit("neiki")
    
    url = "https://api.neiki.dev/v1/enrich"
    headers = {"Authorization": f"Bearer {api_key}"}
    data = {"ioc_type": ioc_type, "ioc_value": ioc_value}
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"Neiki API error: {e.response.status_code} - {e.response.text}", flush=True)
        return None
    except requests.exceptions.RequestException as e:
        print(f"Neiki request error: {str(e)}", flush=True)
        return None


def _get_rss_updates(keyword: str) -> List[Dict[str, str]]:
    """
    Get RSS feed updates matching a keyword.
    
    Args:
        keyword: Keyword to search for in RSS feeds
    
    Returns:
        List of dictionaries with title, link, and summary
    """
    # Hardcoded list of major threat intel RSS feeds
    rss_feeds = [
        "https://www.bleepingcomputer.com/feed/",
        "https://isc.sans.edu/rssfeed_full.xml",
        "https://www.cisa.gov/news.xml",
        "https://krebsonsecurity.com/feed/",
        "https://threatpost.com/feed/",
        "https://www.securityweek.com/rss",
        "https://feeds.feedburner.com/Securityweek",
        "https://www.darkreading.com/rss.xml",
        "https://www.infosecurity-magazine.com/rss/news/",
        "https://www.theregister.com/security/headlines.atom"
    ]
    
    matching_articles = []
    keyword_lower = keyword.lower()
    
    for feed_url in rss_feeds:
        try:
            _rate_limit("rss")
            feed = feedparser.parse(feed_url)
            
            for entry in feed.entries:
                title = entry.get('title', '')
                summary = entry.get('summary', '')
                link = entry.get('link', '')
                
                # Check if keyword appears in title or summary (case-insensitive)
                if keyword_lower in title.lower() or keyword_lower in summary.lower():
                    matching_articles.append({
                        "title": title,
                        "link": link,
                        "summary": summary[:500] if summary else ""  # Limit summary length
                    })
        except Exception as e:
            print(f"Error parsing RSS feed {feed_url}: {str(e)}", flush=True)
            continue
    
    return matching_articles