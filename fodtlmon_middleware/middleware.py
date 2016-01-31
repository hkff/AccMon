"""
django-fodtlmon-middleware version 1.0
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
from django.http import HttpResponse
from django.contrib.auth import *
from django.contrib.auth.models import User
from django.shortcuts import render
from fodtlmon_middleware.whitebox import *
import threading


class FodtlmonMiddleware(object):

    def __init__(self):
        self.monitors = []

    def log_events(self, request, attributes, view=None, response=None):
        predicates = list()
        for l in attributes:
            if isinstance(l, LogAttribute):
                if l.enabled and l.eval_fx is not None:
                    predicates.append(l.eval_fx(request, view=view, response=response))
        return predicates

    def monitor(self, monitors):
        violations = 0
        for m in monitors:
            if m.enabled:
                if m.control_type is Monitor.MonControlType.REAL_TIME:
                    res = m.monitor()
                    if res.get("result") is Boolean3.Bottom:
                        violations += 1
                else:
                    # TODO make it thread safe
                    threading.Thread(target=m.monitor).start()
        return violations

    ############################################
    # 1. Processing an incoming HTTP request
    ############################################
    def process_request(self, request):
        """
        Request intercepting
        :param request:
        :return:
        """
        now = datetime.now()

        if "sysmon/api/" in request.path:  # Do not log and monitor the middleware
            return  # Log it may be usefull for audits

        # pushing the event
        Sysmon.push_event(Event(self.log_events(request, Sysmon.log_http_attributes), step=now))

        # Trigger monitors
        violations = self.monitor(Sysmon.http_monitors)

        if violations > 0:
            return render(request, "pages/access_denied.html")

    ############################################
    # 2. Processing a view after a request
    ############################################
    def process_view(self, request, view, args, kwargs):
        """
        View intercepting
        :param request:
        :param view:
        :param args:
        :param kwargs:
        :return:
        """
        now = datetime.now()
        print("%s %s %s %s" % (request, view.__name__, args, kwargs))
        # return HttpResponse("Your are trying to cheat !")
        # return render(request, "index.html")

    ############################################
    # 3. Processing an HTTP response
    ############################################
    def process_response(self, request, response):
        """
        Response intercepting
        :param request:
        :param response:
        :return:
        """
        now = datetime.now()
        response["KV"] = Sysmon.main_mon.KV
        print(response)
        return response
