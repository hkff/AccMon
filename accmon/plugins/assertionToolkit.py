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


class AtLoggerId(AtLogger):
    name = "Id"
    regexp = r'ApplMessageWrapper@(?P<id>\w+)'


class AtLoggerPiiAttributeName(AtLogger):
    name = "PiiAttributeName"
    regexp = r'piiAttributeName: (?P<id>\w+)'


class AtLoggerPiiOwner(AtLogger):
    name = "PiiOwner"
    regexp = r'piiOwner: (?P<id>\w+)'


class AtLoggerDate(AtLogger):
    name = "Date"
    regexp = r'^\d+-\d+-\d+ \d+:\d+:\d+'


class AtLoggerMsg(AtLogger):
    name = "Message"

    @classmethod
    def log(cls, log, log_type):
        return Predicate.parse("p('x')")


class AtLoggerAccessAttempt(AtLogger):
    name = "AccessAttempt"
    regexp = r'access attempt by subject \'(?P<id>\w+)\': Access (?P<result>\w+) for, for action \'(?P<action>\w+)\''

    @classmethod
    def log(cls, log, log_type):
        res = None
        match = re.search(cls.regexp, log)
        if match is not None:
            res = Predicate(name="%s_%s" % (log_type, cls.name),
                            args=[Constant(match.group('id')), Constant(match.group('result')), Constant(match.group('action'))])
        return res


class AtLoggerSnapshot(AtLogger):
    name = "Snapshot"
    regexp = r'NovaImage\{id=(?P<id>\S*),(.*)<evidenceDetectionTime>(?P<date>(.+)?)</evidenceDetectionTime>'

    @classmethod
    def log(cls, log, log_type):
        res = None
        match = re.search(cls.regexp, log, re.DOTALL)
        if match is not None:
            res = Predicate(name="%s_%s" % (log_type, cls.name),
                            args=[Constant(match.group('id')), Constant(match.group('date'))])
        return res


class AtLoggerDataDeletion(AtLogger):
    name = "DataDeletion"
    regexp = r'.*?PII delete message.*?date: ([\d-]+) ([\d:\.]+).*'

    @classmethod
    def log(cls, log, log_type):
        res = None
        match = re.search(cls.regexp, log)
        if match is not None:
            res = Predicate(name="%s_%s" % (log_type, cls.name),
                            args=[Constant("%s%s" % (match.group(1), match.group(2)))])
        return res


class AtLoggerEvidenceRecordCreated(AtLogger):
    name = "EvidenceRecordCreated"
    regexp = r'evidence_record_created'

    @classmethod
    def log(cls, log, log_type):
        res = None
        match = re.search(cls.regexp, log)
        if match is not None:
            res = Predicate(name="%s_%s" % (log_type, cls.name),
                            args=[Constant("%s" % ('RECORD'))])
        return res


class AtLoggerPolicyViolationDetected(AtLogger):
    name = "PolicyViolationDetected"
    regexp = r'policy_violation_detected (?P<id>\S*)'

    @classmethod
    def log(cls, log, log_type):
        res = None
        match = re.search(cls.regexp, log)
        if match is not None:
            res = Predicate(name="%s_%s" % (log_type, cls.name),
                            args=[Constant("%s" % (match.group('id')))])
        return res


###################################################
# AssertionToolkit main plugin
###################################################
class AssertionToolkit(Remote):
    """
    AssertionToolkit main plugin class
    """
    loggers = [AtLoggerId, AtLoggerPiiAttributeName, AtLoggerPiiOwner, AtLoggerAccessAttempt, AtLoggerSnapshot,
               AtLoggerMsg, AtLoggerDate, AtLoggerDataDeletion, AtLoggerEvidenceRecordCreated,
               AtLoggerPolicyViolationDetected]

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

    AAS_whitelist = ["evidence_record_created", "snapshot_detected", "data_retention_policy_violation_detected",
                     "notification_sent", "policy_violation_detected"]
    AAS_blacklist = ["received_apple_log"]
    APPLE_whitelist = ["received_apple_log"]
    APPLE_blacklist = []

    @staticmethod
    def is_aas_log(log):
        for x in AssertionToolkit.AAS_blacklist:
            if x in log: return False
        for x in AssertionToolkit.AAS_whitelist:
            if x in log: return True
        return False

    @staticmethod
    def is_apple_log(log):
        for x in AssertionToolkit.APPLE_blacklist:
            if x in log: return False
        for x in AssertionToolkit.APPLE_whitelist:
            if x in log: return True
        return False

    @staticmethod
    def get_log_type(log):
        res = "UNKNOWN"
        if AssertionToolkit.is_aas_log(log):
            res = "AAS"
        elif AssertionToolkit.is_apple_log(log):
            res = "APPLE"
        return res

    def handle_request(self, request):
        res = super(AssertionToolkit, self).handle_request(request)
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
        except Exception as e:
            return res + str(e)

    class HTTPRequestHandler(Remote.HTTPRequestHandler):
        pass

