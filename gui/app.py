import os
import json
import subprocess
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

# Paths
BUILD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "build"))
PASS_SO = os.path.join(BUILD_DIR, "libSQLiPass.so")

class RequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve index.html for root
        if self.path == '/':
            self.path = '/templates/index.html'
        return super().do_GET()

    def do_POST(self):
        if self.path == '/analyze':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                if not data or "code" not in data:
                    self.send_error_json(400, "No code provided")
                    return
                
                code = data["code"]
                
                # Write code to a temporary file
                input_cpp = "/tmp/sqli_input.cpp"
                input_ll = "/tmp/sqli_input.ll"
                output_ll = "/tmp/sqli_output.ll"
                
                with open(input_cpp, "w") as f:
                    f.write(code)
                
                # Step 1: Compile to LLVM IR
                compile_cmd = [
                    "clang", "-S", "-emit-llvm", "-O0", "-g",
                    "-Xclang", "-disable-O0-optnone", 
                    input_cpp, "-o", input_ll
                ]
                subprocess.run(compile_cmd, check=True, capture_output=True, text=True)
                
                # Step 2: Run the custom LLVM pass
                opt_cmd = [
                    "opt", f"-load-pass-plugin={PASS_SO}", 
                    "-passes=hello-sqli", input_ll, "-o", output_ll, "-S"
                ]
                
                opt_result = subprocess.run(opt_cmd, cwd="/tmp", capture_output=True, text=True)
                
                cfg_path = "/tmp/cfg_output.json"
                
                if not os.path.exists(cfg_path):
                    self.send_error_json(500, "Failed to generate CFG JSON. LLVM pass may have failed.")
                    return
                    
                with open(cfg_path, "r") as f:
                    cfg_data = json.load(f)
                
                is_vulnerable = "VULNERABILITY DETECTED" in opt_result.stderr
                    
                self.send_response_json({"success": True, "cfg": cfg_data, "is_vulnerable": is_vulnerable})
                
            except subprocess.CalledProcessError as e:
                self.send_error_json(400, f"Compilation failed: {e.stderr}")
            except Exception as e:
                self.send_error_json(500, str(e))
        else:
            self.send_error(404, "Endpoint not found")

    def send_response_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def send_error_json(self, status, message):
        self.send_response_json({"error": message}, status)

if __name__ == "__main__":
    port = 5000
    server_address = ('', port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"Starting server on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        print("Server stopped.")
