"""Module to collect findings from Google Cloud Security Command Center."""

import os
import json
from google.cloud import securitycenter
from google.protobuf.json_format import MessageToDict
import time

# Get organization ID from environment variable
ORGANIZATION_ID = os.environ.get("GCP_ORGANIZATION_ID")

def collect_scc_findings(organization_id, filter_str=None, max_results=None):
    """Collects findings from GCP Security Command Center for a given organization.

    Args:
        organization_id (str): The GCP Organization ID (e.g., 'organizations/12345').
        filter_str (str, optional): SCC filter string (e.g., 'state=\"ACTIVE\"'). 
                                     Defaults to None (all findings).
                                     See: https://cloud.google.com/security-command-center/docs/how-to-api-list-findings#filter-findings
        max_results (int, optional): Maximum number of findings to return. Defaults to None (all).

    Returns:
        dict: A dictionary containing a list of findings under the 'findings' key, 
              or an empty list if an error occurs or no findings are found.
    """
    print(f"Collecting SCC findings for {organization_id}...")
    if not organization_id:
        print("Error: GCP_ORGANIZATION_ID environment variable not set.")
        return {"findings": []}

    all_findings_dict = []
    collected_count = 0

    try:
        # Create a client
        client = securitycenter.SecurityCenterClient()

        # Prepare the request
        finding_result_iterator = client.list_findings(
            request={
                "parent": f"{organization_id}/sources/-", # List findings across all sources
                "filter": filter_str
            }
        )

        # Iterate through findings and convert to dictionaries
        print(f"Iterating through findings (Filter: {filter_str or 'None'})...")
        for i, result in enumerate(finding_result_iterator):
            finding_dict = MessageToDict(result.finding._pb)
            all_findings_dict.append(finding_dict)
            collected_count += 1
            # print(f"  Collected finding {collected_count}: {result.finding.name}") # Verbose logging

            if max_results is not None and collected_count >= max_results:
                print(f"Reached max_results limit ({max_results}).")
                break
            
            # Add a small delay to avoid hitting potential rate limits aggressively
            # time.sleep(0.05)

        print(f"Finished fetching SCC findings. Total collected: {len(all_findings_dict)}")
        return {"findings": all_findings_dict}

    except Exception as e:
        print(f"An error occurred during SCC finding collection: {e}")
        # Consider more specific error handling (e.g., for permissions)
        return {"findings": []}

# Example usage (for direct script execution testing)
if __name__ == "__main__":
    print("Running GCP SCC collector module directly...")
    if not ORGANIZATION_ID:
        print("Error: GCP_ORGANIZATION_ID environment variable is required for direct testing.")
    else:
        # Example: Get active findings only
        active_filter = 'state="ACTIVE"'
        findings_data = collect_scc_findings(ORGANIZATION_ID, filter_str=active_filter, max_results=10)
        
        if findings_data and findings_data.get('findings'):
            print(f"\nSuccessfully collected {len(findings_data['findings'])} findings.")
            # print("Sample finding:")
            # print(json.dumps(findings_data['findings'][0], indent=2))
        else:
            print("\nNo findings collected or an error occurred.")
