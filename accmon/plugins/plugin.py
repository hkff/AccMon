"""
Plugin
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
from accmon.sysmon import *
from django.http import HttpResponse


class Plugin:
    """
    Plugin
    """
    monitors = []

    def __init__(self):
        self.name = self.__class__.__name__
        setattr(self.__class__, "enabled", False)
        setattr(self.__class__, "monitors", [])
        setattr(self.__class__, "main_mon", Fodtlmon("true", Trace()))

    def get_template_args(self):
        return {"name": self.name}

    def handle_request(self, request):
        if request.method == "POST":
            action = request.POST.get('action')
        else:
            action = request.GET.get('action')

        if action == "render":
            return self.render(request)

        return None

    def render(self, request):
        try:
            template_name = self.name + ".html"
            return render(request, "fragments/plugins/" + template_name, {"args": self.get_template_args()})
        except Exception as e:
            return HttpResponse(e)

    @classmethod
    def add_rule(cls, name: str, formula: str, description: str="", violation_formula: str=None, liveness: int=None,
                      control_type=Monitor.MonControlType.POSTERIORI):
        mon = Monitor(name=name, target=Monitor.MonType.GENERIC, location=cls.__name__, kind=Monitor.MonType.GENERIC,
                       formula=formula, description=description, debug=False, povo=True, mon_trace=cls.main_mon.trace,
                       violation_formula=violation_formula, liveness=liveness, control_type=control_type)
        cls.monitors.append(mon)
