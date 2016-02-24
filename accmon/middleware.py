"""
accmon version 1.0
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
from accmon.sysmon import *
import threading

TIMER = 0


class FodtlmonMiddleware(object):
    """

    """
    def log_events(self, request, attributes, view=None, response=None, args=None, kwargs=None):
        predicates = list()
        for l in attributes:
            if isinstance(l, LogAttribute):
                if l.enabled and l.eval_fx is not None:
                    p = l.eval_fx(request=request, view=view, response=response, args=args, kwargs=kwargs)
                    if isinstance(p, Predicate): predicates.append(p)
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
        global TIMER
        now = datetime.now()
        TIMER = time.time()
        if "sysmon/api/" in request.path:  # TODO make this condition secure
            return

        # pushing the event
        Sysmon.push_event(Event(self.log_events(request, Sysmon.log_http_attributes), step=now), Monitor.MonType.HTTP)

        # Check and update KV
        if request.method == 'POST':
            kv = request.POST.get("KV")
            if kv is not None:
                Sysmon.main_mon.update_kv(Sysmon.kv_implementation.parse(kv))
                print(kv)
        elif request.method == 'GET':
            kv = request.GET.get("KV")
            if kv is not None:
                Sysmon.main_mon.update_kv(Sysmon.kv_implementation.parse(kv))
                print(kv)

        # Trigger monitors
        if self.monitor(Sysmon.http_monitors) > 0:
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
        print("%s %s %s %s" % (request, view.__name__, args, kwargs))
        now = datetime.now()

        if "sysmon/api/" not in request.path:
            # pushing the event
            Sysmon.push_event(Event(self.log_events(request, Sysmon.log_view_attributes, view=view,
                                                   args=args, kwargs=kwargs), step=now), Monitor.MonType.VIEW)

            # Trigger monitors
            if self.monitor(Sysmon.views_monitors) > 0:
                return render(request, "pages/access_denied.html")

            # Enable sys tracing
            if "sysmon/" not in request.path:  # TODO make this condition secure
                enabled = next(filter(lambda x: x.enabled, Blackbox.CONTROLS), None)
                if enabled is not None:
                    for control in Blackbox.CONTROLS:
                        if control.enabled:
                            res = control.prepare(request, view, args, kwargs)
                            if res is not None:
                                return render(request, "pages/access_denied.html")

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
        global TIMER
        now = datetime.now()

        if "sysmon/api/" not in request.path:

            # pushing the event
            Sysmon.push_event(Event(self.log_events(request, Sysmon.log_response_attributes, response=response),
                                    step=now), Monitor.MonType.RESPONSE)

            # Trigger monitors
            if self.monitor(Sysmon.response_monitors) > 0:
                return render(request, "pages/access_denied.html")

            # Update KV TODO filter
            if request.method == 'POST':
                kv = request.POST.get("KV")
                if kv is not None:
                    response["KV"] = Sysmon.main_mon.KV
            elif request.method == 'GET':
                kv = request.GET.get("KV")
                if kv is not None:  # Add it to meta ?
                    response["KV"] = Sysmon.main_mon.KV

            print("****************** response time %s " % (time.time() - TIMER))
        return response
