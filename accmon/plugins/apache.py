"""
Apache plugin
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
from accmon.plugins.remote import Remote

from accmon.plugins.plugin import *

apache_import_err = None
try:
    import apache_log_parser
except:
    apache_import_err = "Missing apache_log_parser."


###################################################
# Apache Loggers
###################################################
class ApLogger:
    enabled = True
    name = ""
    regexp = ""
    args_number = 1
    description = ""

    @classmethod
    def log(cls, log, log_type):
        res = None
        try:
            match = re.search(cls.regexp, log)
            if match is not None:
                cts = []
                for x in range(1, cls.args_number+1):
                    cts.append(Constant(match.group(x)))
                res = Predicate(name="%s_%s" % (log_type, cls.name), args=cts)
            return res
        finally:
            return res


###################################################
# Apache main plugin
###################################################
class Apache(Remote):
    """
    Apache main plugin class
    """
    loggers = []

    def __init__(self):
        super().__init__()
        self.server_port = 13000
        self.is_running = False

    def get_template_args(self):
        super_args = super(Remote, self).get_template_args()
        args = {"trace": self.main_mon.trace, "loggers": self.loggers, "remote_is_running": self.is_running,
                "server_port": self.server_port}
        args.update(super_args)
        return args

    def handle_request(self, request):
        res = super(Apache, self).handle_request(request)
        if res is not None: return res

        if request.method == "POST":
            res = "Action not supported !"
            action = request.POST.get('action')
            if action == "run":
                port = request.POST.get('port')
                try:
                    port = int(port)
                except:
                    port = 12000
                res = self.start(port)
            return HttpResponse(res)
        else:
            return HttpResponse("Only POST method is allowed")

    @classmethod
    def handle_req(cls, path, args, method):
        res = "Error"
        try:
            if path.startswith("/event"):
                log = cls.HTTPRequestHandler.get_arg(args, "event", method)
                if log is not None:
                    # Apply loggers
                    e = Event()
                    for logger in cls.loggers:
                        if logger.enabled:
                            p = logger.log(log)
                            if p is not None:
                                e.push_predicate(p)

                    e.step = datetime.now()
                    cls.main_mon.push_event(e)
                    for x in Apache.monitors:
                        x.monitor()
                    return "Pushed"
            return res
        except Exception as e:
            return res + str(e)

    class HTTPRequestHandler(Remote.HTTPRequestHandler):
        pass

