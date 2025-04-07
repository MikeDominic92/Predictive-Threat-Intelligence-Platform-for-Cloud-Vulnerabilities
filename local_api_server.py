import os
import sys
import json
import uuid
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up the path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Get API key from environment or use default development key
# Fixed development API key - DO NOT use this in production!
DEV_API_KEY = "pti-dev-9f4e8d3c-5a7b-4321-9b8a-c7e5d6f3a2b1"

API_KEY = os.environ.get('API_KEY', DEV_API_KEY)
print(f"\n🔑 Using API Key: {API_KEY}")

# Import our prediction function
from src.functions.risk_prediction.main import predict_risk

class APIHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
    def validate_api_key(self):
        """Validates the API key from request headers"""
        # Get API key from request header
        request_api_key = self.headers.get('X-API-Key')
        
        if not request_api_key:
            return False, "Missing API Key in request headers"
        
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(request_api_key, API_KEY):
            print(f"Invalid API key attempt: {request_api_key[:8]}...")
            return False, "Invalid API Key"
        
        return True, ""
        
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-API-Key')
        self.end_headers()
    
    def do_GET(self):
        # Return simple status page for GET requests
        self._set_headers()
        response = {
            "status": "OK",
            "message": "Risk Prediction API is running. Send POST requests to this endpoint.",
            "authentication": "Required - use X-API-Key header",
            "example": {
                "indicator_type": "domain",
                "source": "alienvault",
                "value": "example.com",
                "tags": ["suspicious"]
            }
        }
        self.wfile.write(json.dumps(response).encode())
    
    def do_POST(self):
        # First validate API key
        is_valid_key, key_error = self.validate_api_key()
        if not is_valid_key:
            self._set_headers(401)
            error_response = {
                "error": key_error
            }
            self.wfile.write(json.dumps(error_response).encode())
            return
            
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            # Parse the request JSON
            request_data = json.loads(post_data.decode('utf-8'))
            
            # Validate required fields
            required_fields = ['indicator_type', 'source']
            missing_fields = [f for f in required_fields if f not in request_data]
            
            if missing_fields:
                self._set_headers(400)
                error_response = {
                    "error": f"Missing required fields: {', '.join(missing_fields)}"
                }
                self.wfile.write(json.dumps(error_response).encode())
                return
            
            # Make prediction
            result = predict_risk(request_data)
            
            # Return result
            self._set_headers()
            self.wfile.write(json.dumps(result).encode())
            
        except json.JSONDecodeError:
            self._set_headers(400)
            error_response = {
                "error": "Invalid JSON in request body"
            }
            self.wfile.write(json.dumps(error_response).encode())
        except Exception as e:
            self._set_headers(500)
            error_response = {
                "error": f"Server error: {str(e)}"
            }
            self.wfile.write(json.dumps(error_response).encode())

def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, APIHandler)
    print(f"Starting API server on port {port}...")
    print(f"API is available at: http://localhost:{port}")
    print(f"\n🔑 API Key: {API_KEY}")
    print("\nSample curl command:")
    curl_cmd = f'curl -X POST http://localhost:{port} -H "Content-Type: application/json" -H "X-API-Key: {API_KEY}" -d "{{\\\"indicator_type\\\":\\\"domain\\\",\\\"source\\\":\\\"alienvault\\\",\\\"value\\\":\\\"example.com\\\",\\\"tags\\\":[\\\"suspicious\\\"]}}"'
    print(curl_cmd)
    print("\nPress Ctrl+C to stop the server...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()
        print("Server stopped.")

if __name__ == "__main__":
    run_server()
