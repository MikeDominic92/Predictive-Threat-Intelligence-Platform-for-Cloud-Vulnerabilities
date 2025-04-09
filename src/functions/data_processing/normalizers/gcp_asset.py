# Normalization logic for Google Cloud Asset Inventory data
import datetime
import logging
import re
import json

# Define the target schema fields expected by BigQuery
# (Keep this consistent across normalizers)
NORMALIZED_SCHEMA_KEYS = [
    "source", "indicator_type", "indicator_value", "threat_category", 
    "malicious_verdicts", "total_verdicts", "confidence_score", "severity", 
    "tags", "country", "asn", "asn_owner", "source_reference", 
    "description", "first_seen", "last_seen", "processed_at"
]

def normalize_gcp_asset_data(raw_data):
    """Normalize Google Cloud Asset Inventory data to the standard schema."""
    if not raw_data or not isinstance(raw_data, dict):
        logging.warning("normalize_gcp_asset_data received invalid input.")
        return []

    normalized_indicators = []
    processed_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        assets = raw_data.get("assets", [])
        logging.info(f"Processing {len(assets)} assets from GCP Asset Inventory.")

        for asset in assets:
            # Extract key information from the asset
            asset_type = asset.get("assetType", "")
            asset_name = asset.get("name", "")
            
            # Skip assets without a name or type
            if not asset_name or not asset_type:
                continue
                
            # Extract project ID from asset name
            project_id = extract_project_id(asset_name)
            
            # Generate a console URL for the asset
            source_ref = generate_asset_reference_url(asset)
            
            # Determine indicator type based on asset type
            indicator_type = map_asset_type_to_indicator(asset_type)
            
            # Extract the specific resource name as the indicator value
            indicator_value = extract_asset_indicator_value(asset)
            
            # Extract resource data and metadata
            resource_data = asset.get("resource", {}).get("data", {})
            update_time = asset.get("updateTime")
            
            # Generate a description of the asset
            description = generate_asset_description(asset)
            
            # Generate tags based on asset properties
            tags = generate_tags_from_asset(asset)
            
            # Assign category based on asset type
            threat_category = "cloud_asset"
            
            # Parse creation time if available
            create_time = extract_creation_time(asset)
            
            # For assets, we don't have a severity/confidence like with findings
            # So assign neutral values
            severity = 0
            confidence = 0.5

            # Ensure all schema keys are present, defaulting to None
            normalized_entry = {key: None for key in NORMALIZED_SCHEMA_KEYS}

            normalized_entry.update({
                "source": "gcp_asset",
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "threat_category": threat_category,
                "malicious_verdicts": 0,  # Assets aren't inherently malicious
                "total_verdicts": 1,
                "confidence_score": confidence,
                "severity": severity,
                "tags": tags,
                "country": extract_location(asset),
                "asn": None,
                "asn_owner": None,
                "source_reference": source_ref,
                "description": description,
                "first_seen": create_time or update_time,
                "last_seen": update_time,
                "processed_at": processed_timestamp
            })
            
            normalized_indicators.append(normalized_entry)

    except Exception as e:
        logging.error(f"Error normalizing GCP Asset data: {e}")
        
    return normalized_indicators

def extract_project_id(asset_name):
    """Extract the project ID from an asset name."""
    if not asset_name:
        return None
        
    # Try to extract project ID from asset name patterns
    project_pattern = r"//[^/]+/projects/([^/]+)"
    
    match = re.search(project_pattern, asset_name)
    if match:
        return match.group(1)
            
    return None

def generate_asset_reference_url(asset):
    """Generate a reference URL to the asset in the Google Cloud Console."""
    asset_type = asset.get("assetType", "")
    asset_name = asset.get("name", "")
    
    if not asset_name or not asset_type:
        return None
        
    # Extract project ID to construct console URL
    project_id = extract_project_id(asset_name)
    if not project_id:
        return None
        
    # Generate URLs based on asset type
    if "compute.googleapis.com/Instance" in asset_type:
        instance_name = asset_name.split("/")[-1]
        return f"https://console.cloud.google.com/compute/instancesDetail/zones/global/instances/{instance_name}?project={project_id}"
    elif "storage.googleapis.com/Bucket" in asset_type:
        bucket_name = asset_name.split("/")[-1]
        return f"https://console.cloud.google.com/storage/browser/{bucket_name}?project={project_id}"
    elif "container.googleapis.com/Cluster" in asset_type:
        cluster_name = asset_name.split("/")[-1]
        return f"https://console.cloud.google.com/kubernetes/clusters/details/global/{cluster_name}?project={project_id}"
    elif "sqladmin.googleapis.com" in asset_type:
        instance_name = asset_name.split("/")[-1]
        return f"https://console.cloud.google.com/sql/instances/{instance_name}/overview?project={project_id}"
    else:
        # Generic Asset Inventory URL
        return f"https://console.cloud.google.com/asset-inventory/overview?project={project_id}"

def map_asset_type_to_indicator(asset_type):
    """Map GCP asset type to a standard indicator type."""
    asset_type = asset_type.lower()
    
    if "compute" in asset_type and "instance" in asset_type:
        return "compute"
    elif "storage" in asset_type and "bucket" in asset_type:
        return "storage"
    elif "container" in asset_type or "kubernetes" in asset_type:
        return "container"
    elif "sql" in asset_type or "database" in asset_type:
        return "database"
    elif "iam" in asset_type or "serviceaccount" in asset_type:
        return "account"
    elif "dns" in asset_type:
        return "domain"
    elif "network" in asset_type or "firewall" in asset_type:
        return "network"
    elif "kms" in asset_type or "key" in asset_type:
        return "key"
    else:
        return "gcp_resource"

def extract_asset_indicator_value(asset):
    """Extract the appropriate indicator value from the asset data."""
    asset_name = asset.get("name", "")
    
    # Get the last part of the asset name as the indicator value
    if asset_name:
        parts = asset_name.split("/")
        if parts:
            return parts[-1]
    
    return "unknown"

def generate_asset_description(asset):
    """Generate a human-readable description of the asset."""
    asset_type = asset.get("assetType", "Unknown Type")
    asset_name = asset.get("name", "Unnamed")
    display_name = asset.get("displayName", "")
    
    # Get the short version of the asset name
    short_name = asset_name.split("/")[-1] if asset_name else "unknown"
    
    # Get a friendly version of the asset type
    friendly_type = asset_type.split("/")[-1] if asset_type else "Resource"
    
    # Use the display name if available, otherwise the short name
    name_to_use = display_name if display_name else short_name
    
    return f"GCP {friendly_type}: {name_to_use}"

def generate_tags_from_asset(asset):
    """Generate relevant tags from the asset data."""
    tags = []
    
    # Add asset type as a tag
    asset_type = asset.get("assetType")
    if asset_type:
        # Extract the meaningful part of the asset type
        type_parts = asset_type.split("/")
        if len(type_parts) > 1:
            tags.append(type_parts[-1].lower())
        
        # Add service as a tag
        if "." in asset_type:
            service = asset_type.split(".")[0]
            if service:
                tags.append(service.lower())
    
    # Add project ID as a tag if available
    project_id = extract_project_id(asset.get("name", ""))
    if project_id:
        tags.append(f"project_{project_id}")
    
    # Add location information as a tag if available
    location = extract_location(asset)
    if location:
        tags.append(f"location_{location}")
        
    return tags

def extract_creation_time(asset):
    """Extract the creation time of the asset if available."""
    # Try to find creation time in resource data
    resource_data = asset.get("resource", {}).get("data", {})
    
    # Look for common creation time fields in different resource types
    if "timeCreated" in resource_data:
        return resource_data["timeCreated"]
    elif "creationTimestamp" in resource_data:
        return resource_data["creationTimestamp"]
    elif "createTime" in resource_data:
        return resource_data["createTime"]
        
    # If we can't find a creation time, fallback to update time
    return asset.get("updateTime")

def extract_location(asset):
    """Extract the location (region/zone) of the asset if available."""
    # Try to extract location from resource data
    resource_data = asset.get("resource", {}).get("data", {})
    
    # Look for common location fields in different resource types
    if "zone" in resource_data:
        # Extract just the region part from the zone (e.g., us-central1-a -> us-central1)
        zone = resource_data["zone"]
        if isinstance(zone, str) and "-" in zone:
            parts = zone.split("-")
            if len(parts) >= 2:
                return "-".join(parts[:-1])
        return zone
    elif "region" in resource_data:
        return resource_data["region"]
    elif "location" in resource_data:
        return resource_data["location"]
        
    # Try to extract from asset name for certain resource types
    asset_name = asset.get("name", "")
    location_match = re.search(r"/locations/([^/]+)/", asset_name)
    if location_match:
        return location_match.group(1)
        
    return None
