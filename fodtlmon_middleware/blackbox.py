"""
Blackbox
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
from datetime import datetime
from enum import Enum
import inspect
from django.contrib.auth.models import User


class Blackbox:
    """
    Blackbox class that contains all available controls
    """
    class Severity(Enum):
        UNDEFINED = 0,
        LOW = 1,
        MEDIUM = 2,
        HIGH = 3

    CONTROLS = []
    VIEWS = []
    MODELS = []
    INSTALLED_APPS = []
    MIDDLEWARE_CLASSES = []


########################################################
# Methods calls tracer
########################################################
def HttpResponseBaseIntercepter(fn):
    """
    Django base http response decorator
    :param fn:
    :return:
    """
    def call_fn(*argv, **kwargs):
        res = fn(*argv, **kwargs)

        # Stack inspection
        stack = inspect.stack()
        try:
            # Call the controls
            for control in Blackbox.CONTROLS:
                if control.enabled:
                    control.run(stack)
        finally:
            del stack

        return res
    return call_fn


########################################################
# Blackbox
########################################################
class Control:
    """
    Base control class for blackbox call graph controls
    """
    class Entry:
        def __init__(self, timestamp=None, view="", details=""):
            self.timestamp = datetime.now() if timestamp is None else timestamp
            self.view = view
            self.details = details

    def __init__(self, enabled=False, severity=None):
        self.name = self.__class__.__name__
        self.enabled = enabled
        self.severity = Blackbox.Severity.UNDEFINED if severity is None else severity
        self.entries = []
        self.current_view_name = ""
        self.description = self.__class__.__doc__

    def enable(self):
        pass

    def initialize(self):
        pass

    def prepare(self, request, view, args, kwargs):
        self.current_view_name = view.__name__

    def run(self, stack):
        pass


########################################################
# Controls
########################################################
class VIEWS_INTRACALLS(Control):
    """
    A view should not be called from another one.
    """
    def __init__(self, enabled=False, severity=None):
        super().__init__(enabled=enabled, severity=severity)

    def run(self, stack):
        calle_views = []
        for x in stack:
            if str(x[3]) in Blackbox.VIEWS:
                calle_views.append(x[3])

        if len(calle_views) > 1:
            details = "View %s called from view %s " % (calle_views[1], calle_views[0])
            self.entries.append(Control.Entry(view=self.current_view_name, details=details))


##########################
# OWASP top 10 controls
##########################
class INJECTION(Control):
    """
    A1- Code injection
    """
    pass


class AUTH(Control):
    """
    A2- Broken authentication (privileges escalation checks)
    """
    def initialize(self):
        setattr(self, "user", None)
        from django.db.models.signals import pre_save
        pre_save.connect(self.access_check, dispatch_uid="sysmon.auth.accesscheck")

    def prepare(self, request, view, args, kwargs):
        self.user = request.user
        self.current_view_name = view.__name__

    def access_check(self, sender, **kwargs):
        if issubclass(sender, User):
            i = kwargs.get("instance")
            u = User.objects.filter(username=self.user).first()
            escale = False
            if i is not None:
                if u is None:
                    if i.is_superuser:
                        escale = True
                else:
                    if i.is_superuser and not u.is_superuser:
                        escale=True
                if escale:
                    details = "Privileges escalation the user %s is being admin by a non admin." % i.username
                    self.entries.append(Control.Entry(view=self.current_view_name, details=details))
            # self.user = None


class XSS(Control):
    """
    A3- XSS (Cross-Site Scripting) input sanitizer
    """
    def prepare(self, request, view, args, kwargs):
        # TODO : try to implement owasp XSS rules
        self.current_view_name = view.__name__
        data = {}
        if request.method == 'GET':
            data = request.GET
        elif request.method == 'POST':
            data = request.POST

        for x in data:
            if data.get(x).startswith("javascript"):
                import cgi
                mutable = data._mutable
                data._mutable = True
                #data[x] = "cgi.escape(data.get(x))"
                data._mutable = mutable
                details = "Potential XSS attack on %s with arg %s : %s" % (self.current_view_name, x, data.get(x))
                self.entries.append(Control.Entry(view=self.current_view_name, details=details))
                #return False

    def run(self, stack):
        pass


class IDOR(Control):
    """
    A4- Insecure Direct Object Reference (IDOR).
    """
    def initialize(self):
        from django.db.models.signals import pre_delete, pre_save
        pre_save.connect(self.access_check, dispatch_uid="sysmon.idor.accesscheck")
        pre_delete.connect(self.access_check, dispatch_uid="sysmon.idor.deletecheck")

    def prepare(self, request, view, args, kwargs):
        self.current_view_name = view.__name__
        self.user = request.user

    def access_check(self, sender, **kwargs):
        # details = "A user is being accessed: %s" % sender
        # self.entries.append(Control.Entry(view="_", details=details))
        pass

    def delete_check(self, sender, **kwargs):
        if issubclass(sender, User):
            i = kwargs.get("instance")
            u = User.objects.filter(username=self.user).first()
            if u is not None:
                if i.username != u.username and not i.is_superuser:
                    details = "The user %s is being deleted by a non admin user %s" % (i.username, u.username)
                    self.entries.append(Control.Entry(view="_", details=details))
            else:
                    details = "The user %s is being deleted by a an anonymous user %s" % (i.username, u)
                    self.entries.append(Control.Entry(view="_", details=details))


class MISCONFIG(Control):
    """
    A5- Security Misconfiguration
    """
    def initialize(self):
        from django.conf import settings
        if settings.DEBUG:
            details = "Warning DEBUG mode is enabled, if you are in production you should set DEBUG to False " \
                      "in your settings."
            self.entries.append(Control.Entry(view="_", details=details))


class EXPOS(Control):
    """
    A6- Sensitive Data Exposure
    """
    pass


class ACCESS(Control):
    """
    A7- Missing Function Level Access Control
    """
    pass


class CSRF(Control):
    """
    A8- Cross-site Request Forgery
    """
    def prepare(self, request, view, args, kwargs):
        if hasattr(view, "csrf_exempt"):
            if getattr(view, "csrf_exempt"):
                details = "A view with CSRF exempt is being to be called"
                self.entries.append(Control.Entry(view=view.__name__, details=details))


class COMPONENTS(Control):
    """
    A9- Using Components with Known Vulnerabilities
    """
    pass


class REDIR(Control):
    """
    A10- Insecure Redirect
    """
    pass

#############################################################
# Adding controls to the available controls in the blackbox
#############################################################
Blackbox.CONTROLS = [
    VIEWS_INTRACALLS(enabled=True, severity=Blackbox.Severity.HIGH),
    #INJECTION(enabled=False, severity=Blackbox.Severity.HIGH),
    AUTH(enabled=True, severity=Blackbox.Severity.HIGH),
    XSS(enabled=True, severity=Blackbox.Severity.HIGH),
    IDOR(enabled=True, severity=Blackbox.Severity.HIGH),
    MISCONFIG(enabled=True, severity=Blackbox.Severity.HIGH),
    #EXPOS(enabled=False, severity=Blackbox.Severity.HIGH),
    #ACCESS(enabled=False, severity=Blackbox.Severity.HIGH),
    CSRF(enabled=True, severity=Blackbox.Severity.LOW),
    #COMPONENTS(enabled=False, severity=Blackbox.Severity.HIGH),
    #REDIR(enabled=False, severity=Blackbox.Severity.HIGH),
]
