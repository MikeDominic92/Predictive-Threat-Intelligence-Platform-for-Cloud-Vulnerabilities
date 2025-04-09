# Normalization logic for Google Cloud Security Command Center data
import datetime
import logging
import re

# Define the target schema fields expected by BigQuery
# (Keep this consistent across normalizers)
NORMALIZED_SCHEMA_KEYS = [
    "source", "indicator_type", "indicator_value", "threat_category", 
    "malicious_verdicts", "total_verdicts", "confidence_score", "severity", 
    "tags", "country", "asn", "asn_owner", "source_reference", 
    "description", "first_seen", "last_seen", "processed_at"
]

def normalize_gcp_scc_data(raw_data):
    """Normalize Google Cloud Security Command Center findings to the standard schema."""
    if not raw_data or not isinstance(raw_data, dict):
        logging.warning("normalize_gcp_scc_data received invalid input.")
        return []

    normalized_indicators = []
    processed_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        findings = raw_data.get("findings", [])
        logging.info(f"Processing {len(findings)} findings from GCP SCC data.")

        for finding in findings:
            # Extract key information from the finding
            finding_id = finding.get("name", "").split("/")[-1] if finding.get("name") else ""
            category = finding.get("category", "UNKNOWN")
            resource_name = finding.get("resourceName", "")
            
            # Extract project ID from resource name if available
            project_id = extract_project_id(resource_name)
            
            # Generate a descriptive source reference URL (SCC console link if possible)
            source_ref = generate_scc_reference_url(finding)
            
            # Extract severity and determine indicator type
            severity_level = finding.get("severity", "UNKNOWN")
            indicator_type = map_scc_indicator_type(category, resource_name)
            
            # Determine indicator value (IP, resource name, etc.)
            indicator_value = extract_indicator_value(finding, indicator_type)
            
            # Extract timestamps
            event_time = finding.get("eventTime")
            create_time = finding.get("createTime")
            
            # Generate tags from finding properties
            tags = generate_tags_from_finding(finding)
            
            # Calculate confidence score based on severity and other factors
            confidence = calculate_confidence(finding)
            
            # Map SCC category to standardized threat category
            threat_category = map_scc_category(category)

            # Ensure all schema keys are present, defaulting to None
            normalized_entry = {key: None for key in NORMALIZED_SCHEMA_KEYS}

            normalized_entry.update({
                "source": "gcp_scc",
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "threat_category": threat_category,
                "malicious_verdicts": 1 if severity_level in ["HIGH", "CRITICAL"] else 0,
                "total_verdicts": 1,
                "confidence_score": confidence,
                "severity": map_scc_severity(severity_level),
                "tags": tags,
                "country": None,  # SCC doesn't typically provide geographic info
                "asn": None,
                "asn_owner": None,
                "source_reference": source_ref,
                "description": finding.get("description", ""),
                "first_seen": create_time,
                "last_seen": event_time or create_time,
                "processed_at": processed_timestamp
            })
            
            normalized_indicators.append(normalized_entry)

    except Exception as e:
        logging.error(f"Error normalizing GCP SCC data: {e}")
        
    return normalized_indicators

def extract_project_id(resource_name):
    """Extract the project ID from a GCP resource name."""
    if not resource_name:
        return None
        
    # Try to extract project ID from resource name patterns
    project_patterns = [
        r"projects/([^/]+)",
        r"//cloudresourcemanager\.googleapis\.com/projects/(\d+)",
    ]
    
    for pattern in project_patterns:
        match = re.search(pattern, resource_name)
        if match:
            return match.group(1)
            
    return None

def generate_scc_reference_url(finding):
    """Generate a reference URL to the finding in the Security Command Center console."""
    finding_name = finding.get("name", "")
    if not finding_name:
        return None
        
    # Extract organization ID and finding ID to construct console URL
    parts = finding_name.split("/")
    if len(parts) >= 4 and parts[0] == "organizations":
        org_id = parts[1]
        finding_id = parts[-1]
        return f"https://console.cloud.google.com/security/command-center/findings?organizationId={org_id}&findingId={finding_id}"
        
    return None

def map_scc_indicator_type(category, resource_name):
    """Map SCC finding category to a standard indicator type."""
    # Determine indicator type based on category and resource
    if "DNS" in category or "DOMAIN" in category:
        return "domain"
    elif "IP" in category or "OPEN_SSH" in category or "OPEN_RDP" in category:
        return "ip"
    elif "IAM" in category:
        return "account"
    elif "BUCKET" in category or "storage.googleapis.com" in resource_name:
        return "storage"
    elif "CONTAINER" in category or "container.googleapis.com" in resource_name:
        return "container"
    elif "VIRTUAL_MACHINE" in category or "compute.googleapis.com" in resource_name:
        return "compute"
    elif "SQL" in category or "sqladmin.googleapis.com" in resource_name:
        return "database"
    else:
        return "gcp_resource"

def extract_indicator_value(finding, indicator_type):
    """Extract the appropriate indicator value based on indicator type."""
    # Extract the right value based on indicator type
    resource_name = finding.get("resourceName", "")
    
    # For IP-based findings, try to extract the IP
    if indicator_type == "ip":
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(finding))
        if ip_matches:
            return ip_matches[0]
    
    # For domain-based findings
    if indicator_type == "domain":
        domain_matches = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b", str(finding))
        if domain_matches:
            return domain_matches[0]
    
    # Return resource name as fallback
    if resource_name:
        return resource_name.split("/")[-1]
    
    # Last resort, use finding name
    finding_name = finding.get("name", "")
    if finding_name:
        return finding_name.split("/")[-1]
    
    return "unknown"

def generate_tags_from_finding(finding):
    """Generate relevant tags from the finding data."""
    tags = []
    
    # Add category as a tag
    category = finding.get("category")
    if category:
        tags.append(category.lower().replace(" ", "_"))
    
    # Add severity as a tag
    severity = finding.get("severity")
    if severity:
        tags.append(f"severity_{severity.lower()}")
    
    # Add resource type as a tag if available
    resource_type = None
    resource_name = finding.get("resourceName", "")
    if "compute.googleapis.com" in resource_name:
        resource_type = "compute"
    elif "storage.googleapis.com" in resource_name:
        resource_type = "storage"
    elif "container.googleapis.com" in resource_name:
        resource_type = "container"
    elif "cloudsql.googleapis.com" in resource_name:
        resource_type = "database"
        
    if resource_type:
        tags.append(f"resource_{resource_type}")
    
    # Add mute status as a tag if available
    if finding.get("mute") == "MUTED":
        tags.append("muted")
        
    return tags

def map_scc_category(category):
    """Map SCC finding category to a standard threat category."""
    category = category.upper() if category else ""
    
    # Map common SCC categories to standard threat categories
    if "MALWARE" in category:
        return "malware"
    elif "VULNERABILITY" in category or "CVE" in category:
        return "vulnerability"
    elif "ACCESS" in category or "IAM" in category or "PRIVILEGE" in category:
        return "access_control"
    elif "MISCONFIG" in category or "MISCONFIGURATION" in category:
        return "misconfiguration"
    elif "COMPLIANCE" in category:
        return "compliance"
    elif "DLP" in category or "DATA_LEAK" in category:
        return "data_leak"
    elif "NETWORK" in category or "FIREWALL" in category:
        return "network_security"
    elif "ENCRYPTION" in category or "KMS" in category:
        return "encryption"
    elif "LOGGING" in category or "AUDIT" in category:
        return "logging"
    else:
        return "cloud_security"

def calculate_confidence(finding):
    """Calculate confidence score for GCP SCC finding."""
    # Base confidence based on severity
    severity = finding.get("severity", "").upper()
    if severity == "CRITICAL":
        base_confidence = 0.9
    elif severity == "HIGH":
        base_confidence = 0.8
    elif severity == "MEDIUM":
        base_confidence = 0.6
    elif severity == "LOW":
        base_confidence = 0.4
    else:
        base_confidence = 0.3
        
    # Adjust confidence based on additional factors
    confidence = base_confidence
    
    # If finding is muted, reduce confidence
    if finding.get("mute") == "MUTED":
        confidence -= 0.2
        
    # Ensure confidence is within 0-1 range
    return max(0.0, min(1.0, confidence))

def map_scc_severity(severity_level):
    """Map SCC severity to our standard 0-10 scale."""
    severity_map = {
        "CRITICAL": 9,
        "HIGH": 7,
        "MEDIUM": 5,
        "LOW": 3,
        "UNKNOWN": 1
    }
    
    return severity_map.get(severity_level.upper(), 1)
