import requests
import json

def test_api(base_url="http://localhost:8080"):
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
        "Content-Type": "application/json"
    }
    
    print("Testing Risk Prediction API\n")
    print(f"API URL: {base_url}\n")
    
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
    test_api()
