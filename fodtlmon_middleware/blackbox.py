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


class IO_OP(Control):
    """
    Writing data in disk, may be a data disclosure
    """
    # TODO : use regexp instead
    IO_OPS = [' open', ' print']

    def run(self, stack):
        # TODO
        # Stack.print_stack(file="tmp3") # FIXME duplicated entries
        # r = list(filter(lambda x: x.get("event") == Stack.STACK_EVENTS.LINE and x.get("c_func") in Blackbox.VIEWS
        #                           and len([x for z in self.IO_OPS if z in x.get("line_code")]) > 0, Stack.frames))
        # for x in r:
        #     details = "at line %s : %s " % (x.get("c_lineno"), x.get("line_code"))
        #     self.entries.append(Control.Entry(view=self.current_view_name, details=details))
        for x in stack:
            print(x[3])


class URL_OPEN(Control):
    """
    Performing external http requests
    """
    def run(self, stack):
        # TODO
        # r = list(filter(lambda x: x.get("event") == Stack.STACK_EVENTS.CALL and x.get("c_func") == "urlopen", Stack.frames))
        # for x in r:
        #     details = "In %s at line %s : %s " % (x.get("c_file"), x.get("c_lineno"), x.get("line_code"))
        #     self.entries.append(Control.Entry(view=self.current_view_name, details=details))
        pass


#############################################################
# Adding controls to the available controls in the blackbox
#############################################################
Blackbox.CONTROLS = [
    VIEWS_INTRACALLS(enabled=True, severity=Blackbox.Severity.HIGH),
    # IO_OP(enabled=False, severity=Blackbox.Severity.MEDIUM),
    # URL_OPEN(enabled=False, severity=Blackbox.Severity.HIGH)
]
