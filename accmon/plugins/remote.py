"""
Remote API plugin
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

    def __init__(self):
        super().__init__()
        print(self)
        setattr(self.HTTPRequestHandler, "PLUGIN", self.__class__)
        self.server_port = 10000
        self.is_running = False

    def get_template_args(self):
        super_args = super(Remote, self).get_template_args()
        args = {"remote_is_running": self.is_running}
        args.update(super_args)
        return args

    def handle_request(self, request):
        res = super(Remote, self).handle_request(request)
        if res is not None: return res

        if request.method == "POST":
            res = "Action not supported !"
            action = request.POST.get('action')
            # action = self.HTTPRequestHandler.get_request_arg(request, "action")
            if action == "run":
                port = request.POST.get('port')
                try:
                    port = int(port)
                except:
                    port = 10000
                res = self.start(port)
            return HttpResponse(res)
        else:
            return HttpResponse("Only POST method is allowed")

    # Threading server
    class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
        pass

    # Forking server
    class ForkingSimpleServer(ForkingMixIn, HTTPServer):
        pass

    def start(self, port=10000):
        self.server_port = port
        threading.Thread(target=Remote.run, args=(self,)).start()
        self.is_running = True
        return "Plugin started on port %s " % port

    @staticmethod
    def run(plugin, server_class=ThreadingSimpleServer):
        server_address = ('', plugin.server_port)
        httpd = server_class(server_address, plugin.__class__.HTTPRequestHandler)
        print("Server start on port " + str(plugin.server_port))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("Stopping server...")
        httpd.server_close()

    @classmethod
    def handle_req(cls, path, args, method):
        res = "Error"
        try:
            if path.startswith("/event"):
                e = Event.parse(args.get("event")[0])
                if e is not None:
                    e.step = datetime.now()
                    cls.main_mon.push_event(e)
                    for x in Remote.monitors:
                        x.monitor()
                    return "Pushed"
                else:
                    return "Bad event format !"
            return res
        except:
            return res

    class HTTPRequestHandler(SimpleHTTPRequestHandler):
        """
        Important : to subclass by other plugins that inherit from Remote
        """
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
            res = self.PLUGIN.handle_req(path, args, "GET")
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

            res = self.PLUGIN.handle_req(self.path, args, "POST")
            self.wfile.write(res.encode("utf-8"))
