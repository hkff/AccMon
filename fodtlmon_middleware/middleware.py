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

    def Log(self, request, attribute: Sysmon.LogAttributes):
        args = []

        if attribute is Sysmon.LogAttributes.PATH:
            args.append(Constant('"%s"' % request.path))  # IMPORTANT Parse path as regexp
            return P(request.method, args=args)

        elif attribute is Sysmon.LogAttributes.SCHEME:
            args.append(Constant(request.scheme))

        elif attribute is Sysmon.LogAttributes.USER:
            args.append(Constant(request.user))

        elif attribute is Sysmon.LogAttributes.REMOTE_ADDR:
            args.append(str(request.META.get("REMOTE_ADDR")))

        elif attribute is Sysmon.LogAttributes.CONTENT_TYPE:
            args.append(str(request.META.get("CONTENT_TYPE")))

        elif attribute is Sysmon.LogAttributes.QUERY_STRING:
            arg = str(request.META.get("QUERY_STRING"))
            if arg != '': args.append(Constant(arg))

        return P(attribute.name, args=args)

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

        if "sysmon/api/" in request.path:  # Do not log and monitor the middleware
            return  # Log it may be usefull for audits

        predicates = list()
        # Log the events
        for l in Sysmon.log_attributes:
            predicates.append(self.Log(request, l))

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
        now = datetime.now()
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
        now = datetime.now()
        response["KV"] = Sysmon.main_mon.KV
        print(response)
        return response


