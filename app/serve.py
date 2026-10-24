#!/usr/bin/env python3
"""
Serve the LoRa Mesh Messenger app over localhost so Web Bluetooth
and the Service Worker work correctly in Chrome.

Usage:
  python serve.py          # opens http://localhost:8000 and serves the app
  python serve.py --port 9000   # use a different port

Web Bluetooth requires Chrome and a device with Bluetooth hardware.
"""
import http.server
import socketserver
import webbrowser
import argparse
import os

class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    """Disable caching so changes to index.html are always picked up."""
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Service-Worker-Allowed', '/')
        super().end_headers()

    def log_message(self, fmt, *args):
        pass  # quiet mode – suppress request noise

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Serve the LoRa Mesh Messenger app.')
    parser.add_argument('--port', type=int, default=8000, help='TCP port (default 8000)')
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    with socketserver.TCPServer(('127.0.0.1', args.port), NoCacheHandler) as httpd:
        url = f'http://localhost:{args.port}'
        print(f'Serving LoRa Mesh Messenger at {url}')
        print('Open the URL above in Chrome.  Press Ctrl-C to stop.')
        webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('\nServer stopped.')
