import http.server
import socketserver
import json
import sys

class MockHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress logging to stdout or log if needed
        print(format % args, file=sys.stderr)

    def do_GET(self):
        if self.path == '/aut-num/AS4242421234':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            data = {
                "aut-num/AS4242421234": {
                    "Attributes": [
                        ["aut-num", "AS4242421234"],
                        ["mnt-by", "TEST-MNT(mntner/TEST-MNT)"]
                    ]
                }
            }
            self.wfile.write(json.dumps(data).encode())
        elif self.path == '/mntner/TEST-MNT':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            data = {
                "mntner/TEST-MNT": {
                    "Attributes": [
                        ["mntner", "TEST-MNT"],
                        ["auth", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOBz+SBn8O1744J1XQ3OpwIGmXnkWR9u8prAF5GfIL0B"]
                    ]
                }
            }
            self.wfile.write(json.dumps(data).encode())
        elif self.path == '/aut-num/AS4242421235':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            data = {
                "aut-num/AS4242421235": {
                    "Attributes": [
                        ["aut-num", "AS4242421235"],
                        ["mnt-by", "TEST-MNT-PGP(mntner/TEST-MNT-PGP)"]
                    ]
                }
            }
            self.wfile.write(json.dumps(data).encode())
        elif self.path == '/mntner/TEST-MNT-PGP':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            data = {
                "mntner/TEST-MNT-PGP": {
                    "Attributes": [
                        ["mntner", "TEST-MNT-PGP"],
                        ["auth", "pgp-fingerprint 6B34521F829DA3556974C58DCB9A8CC485675A0E"]
                    ]
                }
            }
            self.wfile.write(json.dumps(data).encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    with socketserver.TCPServer(("127.0.0.1", 8081), MockHandler) as httpd:
        print("Mock registry started on port 8081")
        httpd.serve_forever()
