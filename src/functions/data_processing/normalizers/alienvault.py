# Normalization logic for AlienVault OTX data
import datetime
import logging

# Define the target schema fields expected by BigQuery
# (Keep this consistent across normalizers)
NORMALIZED_SCHEMA_KEYS = [
    "source", "indicator_type", "indicator_value", "threat_category", 
    "malicious_verdicts", "total_verdicts", "confidence_score", "severity", 
    "tags", "country", "asn", "asn_owner", "source_reference", 
    "description", "first_seen", "last_seen", "processed_at"
]

def normalize_alienvault_data(raw_data):
    """Normalize AlienVault OTX data to the standard schema."""
    if not raw_data or not isinstance(raw_data, dict):
        logging.warning("normalize_alienvault_data received invalid input.")
        return []

    normalized_indicators = []
    processed_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        pulses = raw_data.get("pulses", [])
        logging.info(f"Processing {len(pulses)} pulses from AlienVault data.")

        for pulse in pulses:
            pulse_id = pulse.get("id")
            pulse_name = pulse.get("name")
            pulse_description = pulse.get("description", "")
            pulse_tags = pulse.get("tags", [])
            created_ts = pulse.get("created") # OTX timestamp format: "YYYY-MM-DDTHH:MM:SS.ffffff"
            otx_link = f"https://otx.alienvault.com/pulse/{pulse_id}"

            for indicator in pulse.get("indicators", []):
                indicator_type = map_alienvault_type(indicator.get("type"))
                if not indicator_type:
                    continue # Skip unsupported indicator types

                # Basic confidence/severity - refine later
                confidence = calculate_confidence(pulse, indicator)
                severity = calculate_severity(pulse, indicator)
                threat_category = map_alienvault_category(pulse_tags, indicator.get("type"))

                # Ensure all schema keys are present, defaulting to None
                normalized_entry = {key: None for key in NORMALIZED_SCHEMA_KEYS}

                normalized_entry.update({
                    "source": "alienvault",
                    "indicator_type": indicator_type,
                    "indicator_value": indicator.get("indicator"),
                    "threat_category": threat_category,
                    # "malicious_verdicts": None, # Not directly available
                    # "total_verdicts": None, # Not directly available
                    "confidence_score": confidence,
                    "severity": severity,
                    "tags": list(set(pulse_tags)), # Ensure unique tags
                    # "country": None, # Typically not in OTX indicator list
                    # "asn": None,
                    # "asn_owner": None,
                    "source_reference": otx_link,
                    "description": pulse_description or pulse_name, # Use name if description is empty
                    # "first_seen": None, # Not reliably available per indicator
                    "last_seen": created_ts, # Use pulse creation time as last_seen
                    "processed_at": processed_timestamp
                })
                normalized_indicators.append(normalized_entry)

        logging.info(f"Successfully normalized {len(normalized_indicators)} indicators from AlienVault.")
        return normalized_indicators

    except Exception as e:
        logging.error(f"Error during AlienVault normalization: {str(e)}")
        return [] # Return empty list on error to avoid partial data

def map_alienvault_type(otx_type):
    """Map OTX indicator types to our standard types."""
    mapping = {
        "IPv4": "ipv4",
        "IPv6": "ipv6",
        "domain": "domain",
        "hostname": "domain", # Treat hostname as domain
        "URL": "url",
        "FileHash-MD5": "filehash_md5",
        "FileHash-SHA1": "filehash_sha1",
        "FileHash-SHA256": "filehash_sha256",
        # Add more mappings as needed (e.g., CVE, email)
    }
    return mapping.get(otx_type)

def map_alienvault_category(tags, indicator_type):
    """Attempt to map AlienVault tags/type to a standard threat category."""
    tags_lower = [tag.lower() for tag in tags]
    
    if "malware" in tags_lower: return "malware"
    if "ransomware" in tags_lower: return "malware"
    if "phishing" in tags_lower: return "phishing"
    if "c2" in tags_lower or "command and control" in tags_lower: return "c2"
    if "exploit" in tags_lower: return "exploit_kit"
    if "apt" in tags_lower: return "apt"
    if "scan" in tags_lower or "scanner" in tags_lower: return "scanner"
    if "botnet" in tags_lower: return "botnet"
    # Add more specific mappings based on observed tags

    # Generic fallback based on type
    if indicator_type in ["IPv4", "IPv6", "domain", "hostname", "URL"]:
        return "suspicious_network_activity"
    if indicator_type and indicator_type.startswith("FileHash"):
        return "suspicious_file"
        
    return "unknown"

def calculate_confidence(pulse, indicator):
    """Calculate confidence score for AlienVault indicator (placeholder)."""
    # Placeholder - refine this logic based on requirements
    # Factors to consider: Pulse TLP, author reputation, number of references,
    # indicator validation status (if available).
    base_score = 0.5
    if pulse.get("adversary"): base_score += 0.1
    if len(pulse.get("tags", [])) > 3: base_score += 0.1
    # Add more sophisticated logic later
    return min(max(base_score, 0.0), 1.0)

def calculate_severity(pulse, indicator):
    """Calculate severity score for AlienVault indicator (placeholder)."""
    # Placeholder - refine this logic based on requirements
    # Factors to consider: Tags (ransomware, apt, exploit), indicator type,
    # pulse references/context.
    tags = pulse.get("tags", [])
    tags_lower = [tag.lower() for tag in tags]
    high_severity_tags = ["ransomware", "exploit", "zero-day", "apt", "critical"]
    medium_severity_tags = ["malware", "c2", "phishing", "botnet"]

    if any(tag in tags_lower for tag in high_severity_tags):
        return "high"
    elif any(tag in tags_lower for tag in medium_severity_tags):
        return "medium"
    elif len(tags) > 3: # More context might imply medium severity
        return "medium"
    else:
        return "low"
