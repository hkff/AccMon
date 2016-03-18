"""
Assertion Toolkit plugin
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

from accmon.plugins.remote import *


###################################################
# At Loggers
###################################################
class AtLogger:
    enabled = True
    name = ""
    regexp = ""

    @classmethod
    def log(cls, log, log_type):
        res = None
        match = re.search(cls.regexp, log)
        if match is not None:
            res = Predicate(name="%s_%s" % (log_type, cls.name), args=[Constant(match.group(1))])
        return res


class AtLoggerId(AtLogger):
    name = "Id"
    regexp = r'ApplMessageWrapper@(?P<id>\w+)'

    # @classmethod
    # def log(cls, log, log_type):
    #     res = None
    #     match = re.search(r'ApplMessageWrapper@(?P<id>\w+)', log)
    #     if match is not None:
    #         res = Predicate(name="%s_%s" % (log_type, cls.name), args=[Constant(match.group(1))])
    #     return res


class AtLoggerPiiAttributeName(AtLogger):
    name = "PiiAttributeName"
    regexp = r'piiAttributeName: (?P<id>\w+)'

    # @classmethod
    # def log(cls, log, log_type):
    #     res = None
    #     match = re.search(r'piiAttributeName: (?P<id>\w+)', log)
    #     if match is not None:
    #         res = Predicate(name="%s_%s" % (log_type, cls.name), args=[Constant(match.group(1))])
    #     return res


class AtLoggerPiiOwner(AtLogger):
    name = "PiiOwner"
    regexp = r'piiOwner: (?P<id>\w+)'

    # @classmethod
    # def log(cls, log, log_type):
    #     res = None
    #     match = re.search(r'piiOwner: (?P<id>\w+)', log)
    #     if match is not None:
    #         res = Predicate(name="%s_%s" % (log_type, cls.name), args=[Constant(match.group(1))])
    #     return res


class AtLoggerDate(AtLogger):
    enabled = False
    name = "Date"

    @classmethod
    def log(cls, log, log_type):
        return Predicate.parse("p('x')")


class AtLoggerMsg(AtLogger):
    name = "Message"

    @classmethod
    def log(cls, log, log_type):
        return Predicate.parse("p('x')")


###################################################
# AssertionToolkit main plugin
###################################################
class AssertionToolkit(Remote):
    """
    AssertionToolkit main plugin class
    """
    loggers = [AtLoggerId, AtLoggerPiiAttributeName, AtLoggerPiiOwner, AtLoggerDate, AtLoggerMsg]

    def __init__(self):
        super().__init__()
        self.server_port = 13000
        self.is_running = False

    def get_template_args(self):
        super_args = super(Remote, self).get_template_args()
        args = {"trace": self.main_mon.trace, "loggers": self.loggers}
        args.update(super_args)
        return args

    @staticmethod
    def is_aas_log(log):
        return "received_apple_log" not in log and "evidence_record_created" in log

    @staticmethod
    def is_apple_log(log):
        return "received_apple_log" in log and "xml" not in log

    @staticmethod
    def get_log_type(log):
        res = "UNKNOWN"
        if AssertionToolkit.is_aas_log(log):
            res = "AAS"
        elif AssertionToolkit.is_apple_log(log):
            res = "APPLE"
        return res

    def handle_request(self, request):
        if request.method == "POST":
            res = "Action not supported !"
            action = request.POST.get('action')
            # action = self.HTTPRequestHandler.get_request_arg(request, "action")
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
                    log_type = cls.get_log_type(log)
                    # Apply loggers
                    e = Event()
                    for logger in cls.loggers:
                        if logger.enabled:
                            p = logger.log(log, log_type)
                            if p is not None:
                                e.push_predicate(p)

                    e.step = datetime.now()
                    cls.main_mon.push_event(e)
                    for x in AssertionToolkit.monitors:
                        x.monitor()
                    return "Pushed"
            return res
        except:
            return res



