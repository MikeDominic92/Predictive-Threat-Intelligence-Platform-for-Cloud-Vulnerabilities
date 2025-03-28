import os
import json
import requests
from datetime import datetime, timedelta

# Your AlienVault OTX API key
API_KEY = "afe3c379e94165e6c8ccff2bd85a6ffc610bfed7ef7d60da1e37892324bd481c"
API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# Get pulses from yesterday
yesterday = datetime.now() - timedelta(days=1)

# Set up request parameters
headers = {'X-OTX-API-KEY': API_KEY}
params = {
    "modified_since": yesterday.isoformat(),
    "limit": 10
}

print("Testing AlienVault OTX API connection...")
print(f"Using API key: {API_KEY[:5]}...{API_KEY[-5:]}")
print(f"Fetching pulses modified since: {yesterday.isoformat()}")

# Make the request
response = requests.get(API_URL, headers=headers, params=params, timeout=30)

# Check response
if response.status_code == 200:
    data = response.json()
    pulses = data.get('results', [])
    print(f"\nSUCCESS! Fetched {len(pulses)} pulses")
    
    if pulses:
        print("\nFirst pulse details:")
        first = pulses[0]
        print(f"  Name: {first.get('name')}")
        print(f"  Author: {first.get('author', {}).get('username')}")
        print(f"  Created: {first.get('created')}")
        print(f"  Number of indicators: {len(first.get('indicators', []))}")
        print(f"  Tags: {', '.join(first.get('tags', [])[:5])}")
    
    # Check pagination
    if data.get('next'):
        print(f"\nMore pages available at: {data.get('next')}")
    
    print("\nAPI TEST SUCCESSFUL!")
else:
    print(f"\nERROR: API request failed with status code {response.status_code}")
    print(f"Response: {response.text}")
