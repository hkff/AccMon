"""
views
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
from django.shortcuts import render
from django.http import HttpResponse
from fodtlmon_middleware.middleware import *
from django.contrib.auth.decorators import login_required


@login_required
def index(request):
    return render(request, 'index.html')


def index2(request):
    return HttpResponse("kkkkk")


def show_monitors(request):
    return render(request, 'pages/monitors.html', {"monitors": Sysmon.http_monitors + Sysmon.fx_monitors} )


def show_stats(request):
    return render(request, 'pages/stats.html')


def show_mon_details(request, mon_id):
    m = Sysmon.get_mon_by_id(mon_id)
    return render(request, 'pages/monitor.html', {"monitor": m})