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
from django.http import HttpResponse, JsonResponse
from fodtlmon_middleware.middleware import *
from django.contrib.auth.decorators import login_required


##########################
# Sysmon APP
##########################
def login(request):
    return render(request, 'pages/login.html')


#@login_required(login_url='sysmon_login')
def index(request):
    args = {}
    mons = Sysmon.get_mons()
    args["violations_nbr"] = sum(map(lambda x: len(x.violations), mons))
    args["audits_nbr"] = sum(map(lambda x: len(x.audits), mons))
    args["running_mons"] = len(list(filter(lambda x: x.enabled, mons)))
    args["offline_mons"] = len(mons) - args["running_mons"]
    return render(request, 'pages/home.html', args)


def show_monitors(request):
    return render(request, 'pages/monitors.html', {"monitors": Sysmon.get_mons()})


def show_actors(request):
    return render(request, 'pages/actors.html', {"actors": Sysmon.actors, "KV": Sysmon.main_mon.KV})


def show_stats(request):
    mons = Sysmon.get_mons()
    t = len(list(filter(lambda m: m.mon.last is Boolean3.Top, mons)))
    f = len(list(filter(lambda m: m.mon.last is Boolean3.Bottom, mons)))
    u = len(list(filter(lambda m: m.mon.last is Boolean3.Unknown, mons)))
    args = {'mons_true_nbr': t, 'mons_false_nbr': f, 'mons_unknown_nbr': u, 'mons': mons}
    return render(request, 'pages/stats.html', args)


def show_mon_details(request, mon_id):
    m = Sysmon.get_mon_by_id(mon_id)
    return render(request, 'pages/monitor.html', {"monitor": m})


def show_actor_details(request, actor_name):
    a = Sysmon.get_actor_by_name(actor_name)
    return render(request, 'pages/actor.html', {"actor": a})


def show_mon_violations(request, mon_id):
    m = Sysmon.get_mon_by_id(mon_id)
    return render(request, 'pages/violations.html', {"monitor": m})


def show_http_trace(request):
    return render(request, 'pages/full_http_trace.html', {"trace": Sysmon.main_mon.trace})


def change_mon_status(request, mon_id):
    if request.method == "POST":
        m = Sysmon.get_mon_by_id(mon_id)
        status = request.POST.get('status', '')
        if status == "ENABLED":
            m.enabled = True
        elif status == "DISABLED":
            m.enabled = False
        return HttpResponse("Status changed !")
    return HttpResponse("KO")


def mon_violation_audit(request, mon_id, violation_id):
    if request.method == "POST":
        comment = request.POST.get('comment', '')
        verdict = request.POST.get('verdict', '')
        if verdict == "LEGITIMATE":
            verdict = Violation.ViolationStatus.LEGITIMATE
        else:
            verdict = Violation.ViolationStatus.ILLEGITIMATE
            m = Sysmon.get_mon_by_id(mon_id)
            m.trigger_remediation(violation_id)

        Sysmon.audit(mon_id, violation_id, comment, verdict)
        return HttpResponse("audited ! ")
    else:
        m = Sysmon.get_mon_by_id(mon_id)
        v = next(filter(lambda x: x.vid == violation_id, m.violations))
        return render(request, 'pages/audit.html', {"monitor": m, "violation": v})


##########################
# Sysmon API
##########################
def api_get_monitors_updates(request):
    res = {}
    mons = Sysmon.get_mons()
    for m in mons:
        res["%s_status" % m.id] = '<span class="label label-info">Running...</span>'  if m.enabled \
            else '<span class="label label-default ">Stopped</span>'

        if m.mon.last == Boolean3.Unknown:
            res["%s_result" % m.id] = '<span class="label label-default b3res">' + str(m.mon.last) + '</span>'
        elif m.mon.last == Boolean3.Bottom:
            res["%s_result" % m.id] = '<span class="label label-danger b3res">'  + str(m.mon.last) + '</span>'
        else:
            res["%s_result" % m.id] = '<span class="label label-success b3res">'  + str(m.mon.last) + '</span>'

        if m.liveness is not None and m.is_liveness_expired() is not False:
            res["%s_liveness" % m.id] = ('<span class="glyphicon glyphicon-warning-sign btn-group" style="color: '
                                         'orange;" data-toggle="tooltip" title="Liveness formula potentially violated'
                                         ' ahead of ' + str(m.is_liveness_expired()) + ' steps !"></span>')

        res["%s_violations" % m.id] = len(m.violations)
        res["%s_audits" % m.id] = len(m.audits)
    return JsonResponse(res)


def api_get_mon_details(request, mon_id):
    m = Sysmon.get_mon_by_id(mon_id)
    return render(request, 'fragments/monitor.html', {"monitor": m})
