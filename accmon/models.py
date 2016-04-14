"""
models
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

from django.db import models
from datetime import datetime
from hashlib import md5
from enum import Enum
from django.conf import settings
#from fodtlmon_middleware.sysmon import *

# class Audit(models.Model):
#     auditor = ""
#     monitor_id = ""
#     comment = ""
#     verdict = ""
#     trace = ""
#     step = ""
#
#
# class Violation2(models.Model):
#     monitor_id = ""
#     comment = ""
#     trace = ""
#     step = ""


class v2(models.Model):
    pass


class Violation:
    class ViolationStatus(Enum):
        LEGITIMATE = 0,
        UNREAD = 1,
        ILLEGITIMATE = 2,

    def __init__(self, monitor_id, step="", trace="", comment="", timestamp=None):
        self.timestamp = datetime.now() if timestamp is None else timestamp
        self.monitor_id = monitor_id
        self.comment = comment
        self.trace = trace
        self.step = step
        self.audit = ""
        self.verdict = Violation.ViolationStatus.UNREAD
        self.vid = self.compute_hash()
        self.remediation_mon = None

    def compute_hash(self, sid=""):
        return "%s@%s_%s" % (sid, self.monitor_id, md5((str(self.trace)+str(self.step)).encode()).hexdigest())


class Actor:
    class ActorStatus(Enum):
        OFFLINE = 0,
        ONLINE = 1,
        CONNECTED = 2,

        def __str__(self):
            return str(self.name)

    def __init__(self, name, ip_addr, port):
        self.name = name
        self.ip_addr = ip_addr
        self.port = port
        self.formulas = []
        self.status = Actor.ActorStatus.OFFLINE
