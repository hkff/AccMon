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
from fodtlmon_middleware import views

urlpatterns = [
    url(r'^$', views.index, name='sysmon'),
    url(r'^/monitors/$', views.show_monitors, name="monitors"),
    url(r'^/stats/$', views.show_stats, name="stats"),
    url(r'^/monitors/mon_details/(?P<mon_id>.*)/$', views.show_mon_details, name="monitor_details"),
    url(r'^/monitors/mon_violations/(?P<mon_id>.*)/$', views.show_mon_violations, name="monitor_violations"),
    url(r'^/monitors/mon_audits/(?P<mon_id>.*)/violation_audit/(?P<violation_id>.*)/$', views.mon_violation_audit,
        name="monitor_violation_audit"),
    url(r'^/http_trace/$', views.show_http_trace, name="http_trace"),
    url(r'^/monitors/(?P<mon_id>.*)/$', views.change_mon_status, name="mon_change_status"),
]
