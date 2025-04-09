"""Module to collect asset inventory data from Google Cloud Asset Inventory."""

import os
import json
from google.cloud import asset_v1
from google.api_core.exceptions import GoogleAPIError
from google.protobuf.json_format import MessageToDict

# Get organization ID from environment variable
ORGANIZATION_ID = os.environ.get("GCP_ORGANIZATION_ID")

def collect_asset_inventory(organization_id, asset_types=None, content_type="RESOURCE", max_results=1000):
    """Collects asset inventory from Google Cloud for a given organization.

    Args:
        organization_id (str): The GCP Organization ID (e.g., 'organizations/12345').
        asset_types (list, optional): List of asset types to collect.
            Example: ['compute.googleapis.com/Instance', 'storage.googleapis.com/Bucket']
            If None, all assets will be collected.
            See: https://cloud.google.com/asset-inventory/docs/supported-asset-types
        content_type (str, optional): Type of content to return.
            Must be one of: 'RESOURCE', 'IAM_POLICY', 'ORG_POLICY', 'ACCESS_POLICY'.
            Defaults to 'RESOURCE'.
        max_results (int, optional): Maximum number of assets to return. Defaults to 1000.

    Returns:
        dict: A dictionary containing a list of assets under the 'assets' key, 
              or an empty list if an error occurs or no assets are found.
    """
    print(f"Collecting GCP Asset Inventory for {organization_id}...")
    if not organization_id:
        print("Error: GCP_ORGANIZATION_ID environment variable not set.")
        return {"assets": []}

    all_assets = []
    collected_count = 0

    try:
        # Create a client
        client = asset_v1.AssetServiceClient()

        # Set up the request
        request = asset_v1.ListAssetsRequest(
            parent=organization_id,
            content_type=getattr(asset_v1.ContentType, content_type),
            page_size=min(1000, max_results)  # API limit is 1000 per page
        )

        # Add asset types filter if provided
        if asset_types:
            request.asset_types = asset_types
            print(f"Filtering for asset types: {', '.join(asset_types)}")

        # Use pagination to collect all assets up to max_results
        page_iterator = client.list_assets(request=request)
        for page in page_iterator:
            for asset in page.assets:
                # Convert protobuf to dict for easier handling
                asset_dict = MessageToDict(asset._pb)
                all_assets.append(asset_dict)
                collected_count += 1
                
                if collected_count >= max_results:
                    break
            
            if collected_count >= max_results:
                print(f"Reached max_results limit ({max_results}).")
                break

        print(f"Finished fetching GCP assets. Total collected: {len(all_assets)}")
        return {"assets": all_assets}

    except GoogleAPIError as e:
        print(f"Google API Error during asset collection: {e}")
        # Add more specific error handling for permission or quota issues
        if "permission" in str(e).lower():
            print("  Hint: Check that your credentials have cloudasset.assets.listAssets permission.")
        return {"assets": []}
    
    except Exception as e:
        print(f"An unexpected error occurred during asset collection: {e}")
        return {"assets": []}

# Example usage (for direct script execution testing)
if __name__ == "__main__":
    print("Running GCP Asset Inventory collector module directly...")
    
    if not ORGANIZATION_ID:
        print("Error: GCP_ORGANIZATION_ID environment variable is required for direct testing.")
    else:
        # Example: Get compute instances and storage buckets only
        compute_storage_types = [
            'compute.googleapis.com/Instance',
            'storage.googleapis.com/Bucket'
        ]
        
        assets_data = collect_asset_inventory(
            ORGANIZATION_ID, 
            asset_types=compute_storage_types,
            max_results=100
        )
        
        if assets_data and assets_data.get('assets'):
            print(f"\nSuccessfully collected {len(assets_data['assets'])} assets.")
            # Just print the asset names rather than full details
            for i, asset in enumerate(assets_data['assets']):
                print(f"  {i+1}. {asset.get('name', 'Unknown')}")
        else:
            print("\nNo assets collected or an error occurred.")
