"""
urls
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
from django.conf.urls import include, url
from accmon import views

urlpatterns = [
    # Sysmon app #
    url(r'^$', views.index, name='sysmon'),
    url(r'^sysmon/config/$', views.show_config, name='config'),
    url(r'^sysmon/help/$', views.show_help, name='help'),
    url(r'^sysmon/plugins/$', views.show_plugins, name='plugins'),
    url(r'^sysmon/plugin/(?P<plugin>.*)/$', views.plugin, name='plugin'),
    url(r'^sysmon/login$', views.login_view, name='sysmon_login'),
    url(r'^sysmon/logout$', views.logout_view, name='sysmon_logout'),
    url(r'^sysmon/monitors/$', views.show_monitors, name="monitors"),
    url(r'^sysmon/stats/$', views.show_stats, name="stats"),
    url(r'^sysmon/monitors/mon_details/(?P<mon_id>.*)/$', views.show_mon_details, name="monitor_details"),
    url(r'^sysmon/monitors/mon_violations/(?P<mon_id>.*)/$', views.show_mon_violations, name="monitor_violations"),
    url(r'^sysmon/monitors/mon_audits/(?P<mon_id>.*)/violation_audit/(?P<violation_id>.*)/$', views.mon_violation_audit,
        name="monitor_violation_audit"),
    url(r'^sysmon/traces/$', views.show_traces, name="traces"),
    url(r'^sysmon/monitors/(?P<mon_id>.*)/$', views.change_mon_status, name="mon_change_status"),
    url(r'^sysmon/actors/$', views.show_actors, name="actors"),
    url(r'^sysmon/actors/actor_details/(?P<actor_name>.*)/$', views.show_actor_details, name="actor_details"),
    url(r'^sysmon/config/update_log_rule/$', views.update_log_rule, name='update_log_rule'),
    url(r'^sysmon/config/update_control_status/$', views.update_control_status, name='update_control_status'),
    url(r'^sysmon/config/control/(?P<control_name>.*)/$', views.show_control_details, name="control_details"),

    # Sysmon API #
    url(r'^sysmon/api/get_mons_updates/$', views.api_get_monitors_updates, name='get_mons_updates'),
    url(r'^sysmon/api/get_mon_details/(?P<mon_id>.*)/$', views.api_get_mon_details, name="get_mon_details"),
    url(r'^sysmon/api/register_actor_formulas/(?P<actor_name>.*)/$', views.api_register_actor_formulas, name="register_actor_formulas"),

    # Actors API #
    url(r'^sysmon/remote/register_formula/$', views.register_formula, name='register_formula'),

]
