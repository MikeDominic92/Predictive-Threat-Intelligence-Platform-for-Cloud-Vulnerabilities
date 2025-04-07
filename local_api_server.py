import os
import sys
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO

# Set up the path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Import our prediction function
from src.functions.risk_prediction.main import predict_risk

class APIHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        # Return simple status page for GET requests
        self._set_headers()
        response = {
            "status": "OK",
            "message": "Risk Prediction API is running. Send POST requests to this endpoint.",
            "example": {
                "indicator_type": "domain",
                "source": "alienvault",
                "value": "example.com",
                "tags": ["suspicious"]
            }
        }
        self.wfile.write(json.dumps(response).encode())
    
    def do_POST(self):
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
    print("\nSample curl command:")
    print('curl -X POST http://localhost:8080 -H "Content-Type: application/json" -d "{\\"indicator_type\\":\\"domain\\",\\"source\\":\\"alienvault\\",\\"value\\":\\"example.com\\",\\"tags\\":[\\"suspicious\\"]}"')
    print("\nPress Ctrl+C to stop the server...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()
        print("Server stopped.")

if __name__ == "__main__":
    run_server()
