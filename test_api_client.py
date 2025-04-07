import requests
import json
import os
import uuid
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_api(base_url="http://localhost:8080", api_key=None):
    # Get API key from parameter, env var, or use the default development key
    if not api_key:
        # Same default key as in local_api_server.py
        DEV_API_KEY = "pti-dev-9f4e8d3c-5a7b-4321-9b8a-c7e5d6f3a2b1"
        api_key = os.environ.get('API_KEY', DEV_API_KEY)
    
    # Test data
    test_cases = [
        {
            "indicator_type": "domain",
            "value": "malicious-example.com",
            "source": "alienvault",
            "tags": ["suspicious", "phishing"]
        },
        {
            "indicator_type": "ip",
            "value": "10.20.30.40",
            "source": "virustotal",
            "tags": ["malware", "botnet"]
        }
    ]
    
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key
    }
    
    print("Testing Risk Prediction API\n")
    print(f"API URL: {base_url}")
    print(f"Using API Key: {api_key[:8]}...\n")
    
    for i, test_case in enumerate(test_cases):
        print(f"Test Case {i+1}: {test_case['indicator_type']} from {test_case['source']}")
        print(f"Value: {test_case['value']}")
        print(f"Tags: {test_case['tags']}")
        
        try:
            # Make the API request
            response = requests.post(
                base_url,
                headers=headers,
                json=test_case
            )
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print("\nPrediction Result:")
                print(json.dumps(result, indent=2))
            else:
                print(f"\nError Response: {response.text}")
        except Exception as e:
            print(f"\nConnection Error: {e}")
        
        print("\n" + "-"*50 + "\n")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Test the Risk Prediction API with authentication')
    parser.add_argument('--url', type=str, default="http://localhost:8080", help='API URL')
    parser.add_argument('--api-key', type=str, help='API Key for authentication')
    
    args = parser.parse_args()
    test_api(base_url=args.url, api_key=args.api_key)
