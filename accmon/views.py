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
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from accmon.middleware import *
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout, login
from django.contrib.auth.decorators import user_passes_test


##########################
# Sysmon APP
##########################
def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return redirect(index)
            else:
                return render(request, 'pages/login.html')
        else:
            return render(request, 'pages/login.html')
    else:
        return render(request, 'pages/login.html')


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def logout_view(request):
    logout(request)
    return redirect(index)


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def index(request):
    args = {}
    mons = Sysmon.get_mons()
    args["violations_nbr"] = sum(map(lambda x: len(x.violations), mons))
    args["audits_nbr"] = sum(map(lambda x: len(x.audits), mons))
    args["running_mons"] = len(list(filter(lambda x: x.enabled, mons)))
    args["offline_mons"] = len(mons) - args["running_mons"]
    args["apps"] = Blackbox.INSTALLED_APPS
    args["controls"] = Blackbox.CONTROLS
    return render(request, 'pages/home.html', args)


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_monitors(request):
    return render(request, 'pages/monitors.html', {"monitors": Sysmon.get_mons()})


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_help(request):
    return render(request, 'pages/sysmon_help.html')


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_plugins(request):
    args = {"plugins": Sysmon.plugins}
    return render(request, 'pages/plugins.html', args)


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def plugin(request, plugin):
    plugins = list(filter(lambda x: x.__class__.__name__ == plugin, Sysmon.plugins))
    if len(plugins) > 0:
        return plugins[0].handle_request(request)
    else:
        return HttpResponse("Plugin not found !")


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_actors(request):
    return render(request, 'pages/actors.html', {"actors": Sysmon.actors, "KV": Sysmon.main_mon.KV})


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_stats(request):
    mons = Sysmon.get_mons()
    t = len(list(filter(lambda m: m.mon.last is Boolean3.Top, mons)))
    f = len(list(filter(lambda m: m.mon.last is Boolean3.Bottom, mons)))
    u = len(list(filter(lambda m: m.mon.last is Boolean3.Unknown, mons)))
    args = {'mons_true_nbr': t, 'mons_false_nbr': f, 'mons_unknown_nbr': u, 'mons': mons}
    return render(request, 'pages/stats.html', args)


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_config(request):
    args = {"log_http_attributes": Sysmon.log_http_attributes,
            "log_view_attributes": Sysmon.log_view_attributes,
            "log_response_attributes": Sysmon.log_response_attributes,
            "blackbox_controls": Blackbox.CONTROLS}
    return render(request, 'pages/config.html', args)


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_mon_details(request, mon_id):
    m = Sysmon.get_mon_by_id(mon_id)
    return render(request, 'pages/monitor.html', {"monitor": m})


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_actor_details(request, actor_name):
    a = Sysmon.get_actor_by_name(actor_name)
    return render(request, 'pages/actor.html', {"actor": a})


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_mon_violations(request, mon_id):
    m = Sysmon.get_mon_by_id(mon_id)
    return render(request, 'pages/violations.html', {"monitor": m})


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_traces(request):
    args = {"http_trace": Sysmon.main_mon.trace, "view_trace": Sysmon.main_view_mon.trace,
            "response_trace": Sysmon.main_response_mon.trace}
    return render(request, 'pages/traces.html', args)


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def show_control_details(request, control_name):
    control = Sysmon.get_blackbox_control_by_name(control_name)
    return render(request, 'pages/control.html', {"control": control})


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def change_mon_status(request, mon_id):
    if request.method == "POST":
        m = Sysmon.get_mon_by_id(mon_id)
        res = request.POST.get('status', None)

        if res is not None:
            if res == "ENABLED":
                m.enabled = True
            elif res == "DISABLED":
                m.enabled = False
            return HttpResponse("Status changed !")

        res = request.POST.get('controlType', '')
        if res is not None:
            if res == "REAL_TIME":
                m.control_type = Monitor.MonControlType.REAL_TIME
            elif res == "POSTERIORI":
                m.control_type = Monitor.MonControlType.POSTERIORI
            return HttpResponse("Status changed !")
    return HttpResponse("KO")


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
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


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def update_log_rule(request):
    if request.method == "POST":
        kind = request.POST.get('kind', None)
        status = request.POST.get('status', None)
        rule_name = request.POST.get('rule_name', None)
        if (kind and status and rule_name) is not None:
            rule = Sysmon.get_rule_by_name(rule_name, Monitor.MonType[kind])
            if rule is not None:
                if status == "ON":
                    rule.enabled = True
                elif status == "OFF":
                    # Check if all predicates of mons are logged
                    for m in Sysmon.get_mons():
                        predicates = m.mon.formula.walk(filter_type=Predicate)
                        if rule.name in [p.name for p in predicates]:
                            m.location = "Warning predicate is not logged !"
                    rule.enabled = False
                return HttpResponse("Rule updated !")
    return HttpResponse("KO")


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def update_control_status(request):
    if request.method == "POST":
        status = request.POST.get('status', None)
        control_name = request.POST.get('control_name', None)
        if (status and control_name) is not None:
            control = Sysmon.get_blackbox_control_by_name(control_name)
            if control is not None:
                if status == "ON":
                    control.enabled = True
                elif status == "OFF":
                    control.enabled = False
                return HttpResponse("Control updated !")
    return HttpResponse("KO")


##########################
# Sysmon API
##########################
@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def api_get_monitors_updates(request):
    res = {}
    mons = Sysmon.get_mons()
    for m in mons:
        res["%s_status" % m.id] = '<span class="label label-info">Running...</span>' if m.enabled \
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


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def api_get_mon_details(request, mon_id):
    m = Sysmon.get_mon_by_id(mon_id)
    return render(request, 'fragments/monitor.html', {"monitor": m})


@user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login')
def api_register_actor_formulas(request, actor_name):
    Sysmon.register_actor_formulas(actor_name)
    return HttpResponse("ok")


# @user_passes_test(lambda u: u.is_superuser, login_url='sysmon_login') # disabled FOR demo only
@csrf_exempt
def register_formula(request):
    formula = request.POST.get("formula", None)
    if formula is None:
        return HttpResponse("No formula provided !")
    formula_id = request.POST.get("formula_id", None)
    target = request.POST.get("target", None)  # the sender
    kind = request.POST.get("kind", Monitor.MonType.HTTP)
    description = request.POST.get("description", "")
    # TODO change depending on kind
    Sysmon.add_http_rule(formula_id, formula, description=description, location=target)
    return HttpResponse("OK")
