from typing import Dict, List, Any, Optional, Set


def find_deltas(baseline_snapshot: Dict[str, Any], new_report: Dict[str, Any], 
                ioc_type: str) -> List[Dict[str, Any]]:
    """
    Main router function to find deltas between baseline and new report.
    
    Args:
        baseline_snapshot: The baseline JSON from database
        new_report: The new report from connectors
        ioc_type: Type of IOC ("ip", "domain", "hash", "keyword")
    
    Returns:
        List of delta dictionaries. Empty list means no changes.
    """
    if not new_report:
        return []

    if ioc_type == 'ip':
        return _compare_vt_ip(baseline_snapshot, new_report)
    
    elif ioc_type == 'domain':
        return _compare_vt_domain(baseline_snapshot, new_report)
    
    elif ioc_type == 'hash':
        return _compare_vt_hash(baseline_snapshot, new_report)
    
    elif ioc_type == 'keyword':
        return _compare_rss(baseline_snapshot, new_report)
    
    else:
        return []


def _compare_vt_comments(old_report: Optional[Dict], new_report: Optional[Dict]) -> List[Dict[str, Any]]:
    """Compare VirusTotal comments"""
    deltas = []
    if not new_report or not new_report.get('virustotal_comments'):
        return deltas

    try:
        old_comments_data = old_report.get('virustotal_comments', {}).get('data', []) if old_report else []
        new_comments_data = new_report.get('virustotal_comments', {}).get('data', [])

        old_comment_ids = {comment.get('id') for comment in old_comments_data}
        new_comments_map = {comment.get('id'): comment for comment in new_comments_data}
        
        new_comment_ids = set(new_comments_map.keys()) - old_comment_ids
        
        for comment_id in new_comment_ids:
            new_comment = new_comments_map[comment_id]
            comment_text = new_comment.get('attributes', {}).get('text', '')
            if comment_text:
                deltas.append({
                    'field': 'new_vt_comment',
                    'value': comment_text[:500]  # Truncate long comments
                })
    except (KeyError, AttributeError, TypeError) as e:
        print(f"Error comparing VT comments data: {str(e)}", flush=True)
        
    return deltas


def _compare_urlscan(old_report: Optional[Dict], new_report: Optional[Dict]) -> List[Dict[str, Any]]:
    """Compare urlscan.io reports"""
    deltas = []
    if not new_report or not new_report.get('urlscan'):
        return deltas

    try:
        old_results = old_report.get('urlscan', {}).get('results', []) if old_report else []
        new_results = new_report.get('urlscan', {}).get('results', [])

        if len(new_results) > len(old_results):
            deltas.append({
                'field': 'new_urlscan_scan',
                'old': len(old_results),
                'new': len(new_results)
            })
    except (KeyError, AttributeError, TypeError) as e:
        print(f"Error comparing urlscan.io data: {str(e)}", flush=True)
        
    return deltas


def _compare_neiki(old_report: Optional[Dict], new_report: Optional[Dict]) -> List[Dict[str, Any]]:
    """Compare Neiki TIP reports"""
    deltas = []
    if not new_report or not new_report.get('neiki'):
        return deltas

    try:
        old_data = old_report.get('neiki', {}).get('data', {}) if old_report else {}
        new_data = new_report.get('neiki', {}).get('data', {})

        # Compare reputation
        old_rep = old_data.get('reputation')
        new_rep = new_data.get('reputation')
        if old_rep != new_rep and new_rep:
            deltas.append({
                'field': 'neiki_reputation_change',
                'old': old_rep,
                'new': new_rep
            })

        # Compare associated domains
        old_domains = set(old_data.get('associated_domains', []))
        new_domains = set(new_data.get('associated_domains', []))
        added_domains = new_domains - old_domains
        for domain in added_domains:
            deltas.append({
                'field': 'neiki_new_associated_domain',
                'value': domain
            })

        # Compare threat feeds
        old_feeds = {feed.get('source') for feed in old_data.get('threat_feeds', [])}
        new_feeds = {feed.get('source') for feed in new_data.get('threat_feeds', [])}
        added_feeds = new_feeds - old_feeds
        for feed in added_feeds:
            deltas.append({
                'field': 'neiki_new_threat_feed',
                'value': feed
            })

    except (KeyError, AttributeError, TypeError) as e:
        print(f"Error comparing Neiki data: {str(e)}", flush=True)
        
    return deltas


def _compare_vt_ip(old_report: Optional[Dict], new_report: Optional[Dict]) -> List[Dict[str, Any]]:
    """Compare VirusTotal IP address reports"""
    deltas = []
    if not new_report:
        return deltas

    old_data = old_report.get('virustotal') if old_report else None
    new_data = new_report.get('virustotal') if new_report else None

    if not new_data:
        return deltas
    
    if old_data:
        try:
            old_attrs = old_data.get('data', {}).get('attributes', {})
            new_attrs = new_data.get('data', {}).get('attributes', {})
            
            # Check malicious detection stats
            old_stats = old_attrs.get('last_analysis_stats', {})
            new_stats = new_attrs.get('last_analysis_stats', {})
            
            old_malicious = old_stats.get('malicious', 0)
            new_malicious = new_stats.get('malicious', 0)
            
            if new_malicious > old_malicious:
                deltas.append({
                    'field': 'detection_ratio',
                    'old': old_malicious,
                    'new': new_malicious
                })
            
            # Check whois changes
            old_whois = old_attrs.get('whois', '')
            new_whois = new_attrs.get('whois', '')
            if old_whois != new_whois and new_whois:
                deltas.append({
                    'field': 'whois_updated',
                    'old': 'previous',
                    'new': 'updated'
                })
            
            # Check for new communicating files
            old_comm_files = old_data.get('data', {}).get('relationships', {}).get('communicating_files', {})
            new_comm_files = new_data.get('data', {}).get('relationships', {}).get('communicating_files', {})
            
            old_count = old_comm_files.get('data', [])
            new_count = new_comm_files.get('data', [])
            
            if len(new_count) > len(old_count):
                deltas.append({
                    'field': 'new_communicating_files',
                    'old': len(old_count),
                    'new': len(new_count)
                })
            
            # Check for new downloaded files
            old_dl_files = old_data.get('data', {}).get('relationships', {}).get('downloaded_files', {})
            new_dl_files = new_data.get('data', {}).get('relationships', {}).get('downloaded_files', {})
            
            old_dl_count = old_dl_files.get('data', [])
            new_dl_count = new_dl_files.get('data', [])
            
            if len(new_dl_count) > len(old_dl_count):
                deltas.append({
                    'field': 'new_downloaded_files',
                    'old': len(old_dl_count),
                    'new': len(new_dl_count)
                })
        except (KeyError, AttributeError, TypeError) as e:
            print(f"Error comparing VT IP data: {str(e)}", flush=True)

    # Compare urlscan.io data
    deltas.extend(_compare_urlscan(old_report, new_report))

    # Compare Neiki data
    deltas.extend(_compare_neiki(old_report, new_report))

    return deltas


def _compare_vt_domain(old_report: Optional[Dict], new_report: Optional[Dict]) -> List[Dict[str, Any]]:
    """Compare VirusTotal domain reports"""
    deltas = []
    if not new_report:
        return deltas

    old_data = old_report.get('virustotal') if old_report else None
    new_data = new_report.get('virustotal') if new_report else None

    if not new_data:
        return deltas
    
    if old_data:
        try:
            old_attrs = old_data.get('data', {}).get('attributes', {})
            new_attrs = new_data.get('data', {}).get('attributes', {})
            
            # Check malicious detection stats
            old_stats = old_attrs.get('last_analysis_stats', {})
            new_stats = new_attrs.get('last_analysis_stats', {})
            
            old_malicious = old_stats.get('malicious', 0)
            new_malicious = new_stats.get('malicious', 0)
            
            if new_malicious > old_malicious:
                deltas.append({
                    'field': 'detection_ratio',
                    'old': old_malicious,
                    'new': new_malicious
                })
            
            # Check for new resolutions (IP addresses)
            old_resolutions = old_attrs.get('last_dns_records', [])
            new_resolutions = new_attrs.get('last_dns_records', [])
            
            old_ips = {r.get('value', '') for r in old_resolutions if r.get('type') == 'A'}
            new_ips = {r.get('value', '') for r in new_resolutions if r.get('type') == 'A'}
            
            new_ip_addresses = new_ips - old_ips
            if new_ip_addresses:
                for ip in new_ip_addresses:
                    deltas.append({
                        'field': 'new_resolution',
                        'value': ip
                    })
        
        except (KeyError, AttributeError, TypeError) as e:
            print(f"Error comparing VT domain data: {str(e)}", flush=True)

    # Compare comments
    deltas.extend(_compare_vt_comments(old_report, new_report))

    # Compare urlscan.io data
    deltas.extend(_compare_urlscan(old_report, new_report))
    
    # Compare Neiki data
    deltas.extend(_compare_neiki(old_report, new_report))
    
    return deltas


def _compare_vt_hash(old_report: Dict[str, Any], new_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compare VirusTotal and MalwareBazaar hash reports"""
    deltas = []
    if not new_report:
        return deltas
    
    # Compare VirusTotal data
    old_vt = old_report.get('virustotal') if old_report else None
    new_vt = new_report.get('virustotal') if new_report else None
    
    if old_vt and new_vt:
        try:
            old_attrs = old_vt.get('data', {}).get('attributes', {})
            new_attrs = new_vt.get('data', {}).get('attributes', {})
            
            # Check malicious detection stats
            old_stats = old_attrs.get('last_analysis_stats', {})
            new_stats = new_attrs.get('last_analysis_stats', {})
            
            old_malicious = old_stats.get('malicious', 0)
            new_malicious = new_stats.get('malicious', 0)
            
            if new_malicious > old_malicious:
                deltas.append({
                    'field': 'detection_ratio',
                    'old': old_malicious,
                    'new': new_malicious
                })
            
            # Check for new signatures
            old_sigs = old_attrs.get('signature_info', {})
            new_sigs = new_attrs.get('signature_info', {})
            
            if old_sigs != new_sigs and new_sigs:
                deltas.append({
                    'field': 'signature_info_updated',
                    'old': 'previous',
                    'new': 'updated'
                })
            
            # Check for new contacted domains
            old_contacts = old_vt.get('data', {}).get('relationships', {}).get('contacted_domains', {})
            new_contacts = new_vt.get('data', {}).get('relationships', {}).get('contacted_domains', {})
            
            old_contact_domains = old_contacts.get('data', [])
            new_contact_domains = new_contacts.get('data', [])
            
            if len(new_contact_domains) > len(old_contact_domains):
                deltas.append({
                    'field': 'new_contacted_domains',
                    'old': len(old_contact_domains),
                    'new': len(new_contact_domains)
                })
            
            # Check for new contacted IPs
            old_contact_ips = old_vt.get('data', {}).get('relationships', {}).get('contacted_ips', {})
            new_contact_ips = new_vt.get('data', {}).get('relationships', {}).get('contacted_ips', {})
            
            old_ips = old_contact_ips.get('data', [])
            new_ips = new_contact_ips.get('data', [])
            
            if len(new_ips) > len(old_ips):
                deltas.append({
                    'field': 'new_contacted_ips',
                    'old': len(old_ips),
                    'new': len(new_ips)
                })
        
        except (KeyError, AttributeError, TypeError) as e:
            print(f"Error comparing VT hash data: {str(e)}", flush=True)

    # Compare comments
    deltas.extend(_compare_vt_comments(old_report, new_report))

    # Compare MalwareBazaar data
    old_mb = old_report.get('malwarebazaar') if old_report else None
    new_mb = new_report.get('malwarebazaar') if new_report else None
    
    if old_mb and new_mb:
        try:
            old_tags = set(old_mb.get('data', [{}])[0].get('tags', []))
            new_tags = set(new_mb.get('data', [{}])[0].get('tags', []))
            
            new_tag_set = new_tags - old_tags
            if new_tag_set:
                for tag in new_tag_set:
                    deltas.append({
                        'field': 'new_mb_tag',
                        'value': tag
                    })
            
            # Check for signature changes
            old_sig = old_mb.get('data', [{}])[0].get('signature', '')
            new_sig = new_mb.get('data', [{}])[0].get('signature', '')
            
            if old_sig != new_sig and new_sig:
                deltas.append({
                    'field': 'mb_signature_updated',
                    'old': old_sig,
                    'new': new_sig
                })
        
        except (KeyError, AttributeError, TypeError, IndexError) as e:
            print(f"Error comparing MB hash data: {str(e)}", flush=True)
    
    # Compare Neiki data
    deltas.extend(_compare_neiki(old_report, new_report))
    
    return deltas


def _compare_rss(old_data: Dict[str, Any], new_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compare RSS feed results"""
    deltas = []
    if not new_data:
        return deltas
    
    old_articles = old_data.get('rss', [])
    new_articles = new_data.get('rss', [])
    
    if not isinstance(old_articles, list):
        old_articles = []
    if not isinstance(new_articles, list):
        new_articles = []
    
    # Get set of old article links
    old_links: Set[str] = {article.get('link', '') for article in old_articles if article.get('link')}
    
    # Find new articles
    for article in new_articles:
        link = article.get('link', '')
        if link and link not in old_links:
            deltas.append({
                'field': 'new_article',
                'value': article.get('title', 'Unknown'),
                'link': link
            })
    
    return deltas