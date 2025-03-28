# Normalization logic for VirusTotal data
import datetime
import logging
import time 

# Define the target schema fields expected by BigQuery
# (Keep this consistent across normalizers)
NORMALIZED_SCHEMA_KEYS = [
    "source", "indicator_type", "indicator_value", "threat_category", 
    "malicious_verdicts", "total_verdicts", "confidence_score", "severity", 
    "tags", "country", "asn", "asn_owner", "source_reference", 
    "description", "first_seen", "last_seen", "processed_at"
]

def normalize_virustotal_data(raw_data):
    """Normalize VirusTotal IP Address report data to the standard schema."""
    if not raw_data or not isinstance(raw_data, list):
        logging.warning("normalize_virustotal_data received invalid input format (expected list).")
        return []

    normalized_indicators = []
    processed_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    logging.info(f"Processing {len(raw_data)} reports from VirusTotal data.")
    for report in raw_data:
        try:
            data = report.get("data")
            if not data or data.get("type") != "ip_address":
                logging.warning(f"Skipping invalid or non-IP report item: {report.get('id', 'N/A')}")
                continue

            attributes = data.get("attributes", {})
            ip_address = data.get("id")
            vt_link = f"https://www.virustotal.com/gui/ip-address/{ip_address}"

            # Extract core stats
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            malicious_count = last_analysis_stats.get("malicious", 0)
            suspicious_count = last_analysis_stats.get("suspicious", 0)
            harmless_count = last_analysis_stats.get("harmless", 0)
            undetected_count = last_analysis_stats.get("undetected", 0)
            total_engines = sum(last_analysis_stats.values())

            # Calculate confidence, severity, and category
            confidence = calculate_vt_confidence(malicious_count, suspicious_count, total_engines)
            severity = calculate_vt_severity(malicious_count, suspicious_count)
            threat_category = map_vt_category(malicious_count, suspicious_count, harmless_count, attributes)

            # Extract additional useful fields
            tags = extract_vt_tags(attributes)
            country = attributes.get("country")
            asn = attributes.get("asn")
            as_owner = attributes.get("as_owner")
            last_analysis_ts_unix = attributes.get("last_analysis_date") # Unix timestamp
            last_seen_ts = datetime.datetime.fromtimestamp(last_analysis_ts_unix, tz=datetime.timezone.utc).isoformat() if last_analysis_ts_unix else None
            # description = attributes.get("whois") # Whois can be very long, maybe summarize or omit?
            description = f"VT analysis: M:{malicious_count}, S:{suspicious_count}, H:{harmless_count}, U:{undetected_count}"

            # Ensure all schema keys are present, defaulting to None
            normalized_entry = {key: None for key in NORMALIZED_SCHEMA_KEYS}

            normalized_entry.update({
                "source": "virustotal",
                "indicator_type": "ipv4", # Assuming IPv4 for now, could check format
                "indicator_value": ip_address,
                "threat_category": threat_category,
                "malicious_verdicts": malicious_count, 
                "total_verdicts": total_engines, 
                "confidence_score": confidence,
                "severity": severity,
                "tags": list(set(tags)), # Ensure unique tags
                "country": country, 
                "asn": asn, 
                "asn_owner": as_owner,
                "source_reference": vt_link,
                "description": description, 
                # "first_seen": None, # Not directly available in IP report
                "last_seen": last_seen_ts, 
                "processed_at": processed_timestamp
            })
            normalized_indicators.append(normalized_entry)

        except Exception as e:
            logging.error(f"Error normalizing VirusTotal report for {report.get('id', 'N/A')}: {str(e)}")
            # Continue processing other reports

    logging.info(f"Successfully normalized {len(normalized_indicators)} indicators from VirusTotal.")
    return normalized_indicators

def calculate_vt_confidence(malicious_count, suspicious_count, total_engines):
    """Calculate confidence score based on VT results."""
    if total_engines == 0: return 0.0
    
    # Weighted score: malicious counts more than suspicious
    weighted_bad = malicious_count + (suspicious_count * 0.5)
    confidence = weighted_bad / total_engines
    
    # Simple ratio alternative:
    # confidence = malicious_count / total_engines
    
    return min(max(confidence, 0.0), 1.0)

def calculate_vt_severity(malicious_count, suspicious_count):
    """Calculate severity based on VT results."""
    if malicious_count >= 10:
        return "high"
    elif malicious_count > 0:
        return "medium"
    elif suspicious_count > 0:
        return "low"
    else:
        return "informational" # Or potentially "low" if harmless > 0

def map_vt_category(malicious_count, suspicious_count, harmless_count, attributes):
    """Attempt to determine a primary threat category from VT results."""
    if malicious_count > 0:
        # Look for specific categories in engine results (more reliable than tags)
        categories = set()
        for engine, result in attributes.get("last_analysis_results", {}).items():
            cat = result.get("category")
            if cat and cat != "undetected" and cat != "harmless" and cat != "timeout":
                 categories.add(cat.lower())
        
        if "malware" in categories: return "malware"
        if "phishing" in categories: return "phishing"
        if "suspicious" in categories and malicious_count > suspicious_count: 
             # If more malicious than suspicious, lean towards a stronger category if possible
             # Try mapping based on engine names or results if needed here
             pass # Placeholder for more detailed mapping
        if categories: # Return the most common/important if multiple exist
             return sorted(list(categories))[0] # Simple alphabetical sort for now
        
        return "malicious_generic" # Fallback if only malicious count is positive

    if suspicious_count > 0:
        return "suspicious_generic"
    if harmless_count > 0:
        return "benign"
        
    return "unknown"

def extract_vt_tags(attributes):
    """Extract meaningful tags from VirusTotal IP attributes (placeholder)."""
    tags = []
    # Example: Add country if available
    if attributes.get("country"): tags.append(f"geo:{attributes['country']}")
    # Example: Add ASN owner if available
    if attributes.get("as_owner"): tags.append(f"asn_owner:{attributes['as_owner']}") 
    
    # Potentially add categories from analysis results
    categories = set()
    for engine, result in attributes.get("last_analysis_results", {}).items():
        cat = result.get("category")
        if cat and cat != "undetected" and cat != "harmless" and cat != "timeout":
            categories.add(cat.lower())
    tags.extend(list(categories))
    
    # Add more tag extraction logic based on available attributes
    return list(set(tags))
