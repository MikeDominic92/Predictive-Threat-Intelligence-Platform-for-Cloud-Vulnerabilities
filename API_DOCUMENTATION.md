# Risk Prediction API Documentation

## Authentication

The Risk Prediction API requires API key authentication to ensure only authorized users can access the service.

### API Key Header

Include your API key in all requests using the `X-API-Key` HTTP header:

```http
X-API-Key: your-api-key-here
```

### Local Development

For local development and testing, the API uses a fixed development API key:

```text
pti-dev-9f4e8d3c-5a7b-4321-9b8a-c7e5d6f3a2b1
```

**⚠️ Warning**: Never use the development API key in production environments.

### Production Deployment

When deploying to Google Cloud Functions, set the `API_KEY` environment variable to a secure, randomly generated value. You can generate a secure key using Python:

```python
import uuid
print(str(uuid.uuid4()))
```

## API Endpoints

### Risk Prediction

**Endpoint**: `/`  
**Method**: POST  
**Content-Type**: application/json

**Request Body**:

```json
{
  "indicator_type": "domain",
  "source": "alienvault",
  "value": "example.com",
  "tags": ["suspicious"]
}
```

Required fields:

- `indicator_type`: Type of the threat indicator (domain, ip, url, etc.)
- `source`: Data source of the indicator (alienvault, virustotal, etc.)

Optional fields:

- `value`: The actual indicator value
- `tags`: List of tags associated with the indicator

**Response (200 OK)**:

```json
{
  "indicator": {
    "type": "domain",
    "value": "example.com",
    "source": "alienvault",
    "tags": ["suspicious"]
  },
  "prediction": {
    "risk_level": "LOW",
    "confidence": 75.5,
    "feature_importance": {
      "feature1": 0.35,
      "feature2": 0.25
    }
  },
  "model_info": {
    "model_type": "RandomForestClassifier",
    "version": "1.0"
  }
}
```

**Error Responses**:

- 401 Unauthorized: Missing or invalid API key
- 400 Bad Request: Missing required fields or invalid request format
- 500 Internal Server Error: Server-side error occurred

## Example Usage

### cURL

```bash
curl -X POST https://your-cloud-function-url \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{"indicator_type":"domain","source":"alienvault","value":"example.com","tags":["suspicious"]}'
```

### Python

```python
import requests

api_url = "https://your-cloud-function-url"
api_key = "your-api-key-here"

headers = {
    "Content-Type": "application/json",
    "X-API-Key": api_key
}

data = {
    "indicator_type": "domain",
    "source": "alienvault",
    "value": "example.com",
    "tags": ["suspicious"]
}

response = requests.post(api_url, headers=headers, json=data)
prediction = response.json()
print(prediction)
```

## Security Best Practices

1. **Keep API keys secure**: Never expose API keys in client-side code or public repositories.
2. **Use HTTPS**: Always use HTTPS to encrypt data in transit.
3. **Rotate keys periodically**: Create a process to rotate API keys regularly.
4. **Limit key permissions**: In production, use the principle of least privilege for API keys.
5. **Monitor API usage**: Implement logging to track and monitor API usage for suspicious activity.
