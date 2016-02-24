"""
System plugin
Copyright (C) 2016 Walid Benghabrit

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from accmon.plugins.plugin import *
from http.server import SimpleHTTPRequestHandler
from http.server import HTTPServer
from urllib.parse import urlparse, parse_qs
from socketserver import ThreadingMixIn, ForkingMixIn
import threading


class Remote(Plugin):
    server_port = 10000

    def __init__(self):
        super().__init__()

    def handle_request(self, request):
        pass

    # Threading server
    class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
        pass

    # Forking server
    class ForkingSimpleServer(ForkingMixIn, HTTPServer):
        pass

    @staticmethod
    def start(port=10000):
        Remote.server_port = port
        threading.Thread(target=Remote.run).start()

    @staticmethod
    def run(server_class=ThreadingSimpleServer):
        server_address = ('', Remote.server_port)
        httpd = server_class(server_address, Remote.HTTPRequestHandler)
        print("Server start on port " + str(Remote.server_port))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("Stopping server...")
        httpd.server_close()

    class HTTPRequestHandler(SimpleHTTPRequestHandler):

        @staticmethod
        def get_arg(args, name, method):
            try:
                if method == "GET":
                    return args[name]
                elif method == "POST":
                    return args[name][0]
                else:
                    return "Method error"
            except:
                return None

        def do_GET(self):
            # print("[GET] " + self.path)
            p = self.path
            k = urlparse(p).query
            args = parse_qs(k)
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            path = p.replace(k, "")
            if path[-1] == "?":
                path = path[:-1]
            res = self.handle_req(path, args, "GET")
            self.wfile.write(res.encode("utf-8"))

        def do_POST(self):
            k = urlparse(self.path).query
            var_len = int(self.headers['Content-Length'])
            post_vars = self.rfile.read(var_len).decode('utf-8')
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            if len(post_vars) == 0:
                args = parse_qs(k)
            else:
                args = parse_qs(post_vars, encoding="utf8")

            res = self.handle_req(self.path, args, "POST")
            self.wfile.write(res.encode("utf-8"))

        def handle_req(self, path, args, method):
            res = "Error"
            try:
                if path.startswith("/event"):
                    e = Event.parse(args.get("event")[0])
                    e.step = datetime.now()
                    if e is not None:
                        Remote.main_mon.push_event(e)
                        for x in Remote.monitors:
                            x.monitor()
                        return "Pushed"
                    else:
                        return "Bad event format !"
                return res
            except:
                return res
