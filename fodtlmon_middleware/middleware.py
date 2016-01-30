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

    def process_request(self, request):
        """
        Request intercepting
        :param request:
        :return:
        """
        ####
        # Adding HTTP request events
        ####
        now = datetime.now()

        # if "sysmon/" in request.path:  # Do not log and monitor the middleware
        #     return  # Log it may be usefull for audits

        # TODO make it in a customizable list for the user
        predicates = list()
        # Request
        predicates.append(P(request.method, args=[Constant('"%s"' % request.path)]))  # IMPORTANT Parse path as regexp
        predicates.append(P("SCHEME", args=[Constant(request.scheme)]))
        # Logged user
        predicates.append(P("USER", args=[Constant(str(request.user))]))
        # Meta
        predicates.append(P("REMOTE_ADDR", args=[Constant(str(request.META.get("REMOTE_ADDR")))]))
        predicates.append(P("CONTENT_TYPE", args=[Constant(str(request.META.get("CONTENT_TYPE")))]))

        arg = str(request.META.get("QUERY_STRING"))
        args = [] if arg == '' else [Constant(arg)]
        predicates.append(P("QUERY_STRING", args=args))

        # pushing the event
        Sysmon.push_event(Event(predicates, step=now))

        # Trigger monitors
        threading.Thread(target=Sysmon.monitor_http_rules).start()

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
        # return HttpResponse("Your are trying to cheat !")
        # return render(request, "index.html")

    def process_response(self, request, response):
        """
        Response intercepting
        :param request:
        :param response:
        :return:
        """
        response["KV"] = Sysmon.main_mon.KV
        print(response)
        return response


