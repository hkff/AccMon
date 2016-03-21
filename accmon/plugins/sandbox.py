"""
Sandbox plugin
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
from accmon.plugins.plugin import *


class Sandbox(Plugin):

    def __init__(self):
        super().__init__()
        self.traces = ['HTTP', 'VIEW', 'RESPONSE']

    def handle_request(self, request):
        res = super(Sandbox, self).handle_request(request)
        if res is not None: return res

        if request.method == "POST":
            res = "Action not supported !"
            action = request.POST.get('action')
            if action == "monitor":
                formula = request.POST.get('formula')
                trace = request.POST.get('trace')
                r = self.monitor(formula, trace)
                res = r
            return HttpResponse(res)
        else:
            return HttpResponse("Only POST method is allowed")

    def get_template_args(self):
        super_args = super(Sandbox, self).get_template_args()
        trace_providers = ['HTTP', 'VIEW', 'RESPONSE']
        args = {"sandbox_trace_providers": trace_providers}
        args.update(super_args)
        return args

    def monitor(self, formula, trace):
        tr = ""
        if trace in self.traces:
            if trace == 'HTTP': tr = Sysmon.main_mon.trace
            elif trace == 'VIEW': tr = Sysmon.main_view_mon.trace
            elif trace == 'RESPONSE': tr = Sysmon.main_response_mon.trace
        else:
            tr = Trace().parse(trace)
        fl = FodtlParser.parse(formula)
        mon = Fodtlmon(fl, tr)
        return mon.monitor()
