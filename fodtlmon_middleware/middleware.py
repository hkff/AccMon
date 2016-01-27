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

class FodtlmonMiddleware(object):

    def __init__(self):
        self.monitors = []

    def process_request(self, request):
        """
        Request intercepting
        :param request:
        :return:
        """
        print("hahah evil %s user %s" % (request, request.user.id))
        print(User.objects.filter(id=request.user.id))
        Sysmon.monitor_http_rules()

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
        response["VCLOCK"] = "{true}"
        print(response)
        return response


