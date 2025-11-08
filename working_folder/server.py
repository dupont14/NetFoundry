from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

os.chdir('.')  # Change this to your directory
server = HTTPServer(('localhost', 8000), CORSRequestHandler)
print('Server running on http://localhost:8000')
server.serve_forever()
