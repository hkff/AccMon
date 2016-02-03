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
from django.http import HttpResponse
from django.conf import settings
from django.core.urlresolvers import RegexURLResolver, RegexURLPattern, get_resolver


########################################################
# Methods calls tracer
########################################################

class Stack:
    """
    Execution stack
    """
    frames = []

    class STACK_EVENTS(Enum):
        CALL = 0,
        RETURN = 1


    @staticmethod
    def frame_to_dict(frame):
        c_back = None if frame.f_back is None else Stack.frame_to_dict(frame.f_back)
        c_func = frame.f_code.co_name
        c_file = frame.f_code.co_filename
        c_lineinfo = frame.f_lineno
        c_class = frame.f_locals['self'].__class__.__name__ if 'self' in frame.f_locals else ''
        c_module = frame.f_locals['self'].__class__.__module__ if 'self' in frame.f_locals else ''
        return {"event": -1, "c_func": c_func, "c_file": c_file, "c_lineinfo": c_lineinfo,
                "c_class": c_class, "c_c_module": c_module, "parent": c_back}

    @staticmethod
    def print_stack(file=None):
        if file is None:
            for x in Stack.frames:
                p = '' if x.get("parent") is None else x.get("parent").get("c_func")
                print("%s %s from %s" % (x.get("event").name, x.get("c_func"), p))
        else:
            with open(file, "w+") as f:
                for x in Stack.frames:
                    p = '' if x.get("parent") is None else x.get("parent").get("c_func")
                    f.write("%s %s from %s\n" % (x.get("event").name, x.get("c_func"), p))

    @staticmethod
    def get_func_call(func_name):
        return filter(lambda x: x.get("event") == Stack.STACK_EVENTS.CALL and x.get("c_func") == func_name, Stack.frames)


def view_tracer(frame, event, arg):
    """
    Python tracer
    :param frame:
    :param event:
    :param arg:
    :return:
    """
    try:
        # Current frame details
        c_frame = Stack.frame_to_dict(frame.f_back)

        if event == 'call' or event == 'c_call':
            c_frame['event'] = Stack.STACK_EVENTS.CALL
            Stack.frames.append(c_frame)
            return view_tracer

        elif event == 'return':
            c_frame['event'] = Stack.STACK_EVENTS.RETURN
            Stack.frames.append(c_frame)
    except:
        print("--------------- Error ---------")


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

    def run(self):
        pass


class Blackbox:
    """
    Blackbox class that contains all available controls
    """
    class Severity(Enum):
        UNDEFINED = 0,
        LOW = 1,
        MEDIUM = 2,
        HIGH = 3

    controls = []


########################################################
# Controls
########################################################
class VIEWS_INTRACALLS(Control):
    """
    A view should not be called from another one.
    """
    def __init__(self, enabled=False, severity=None):
        super().__init__(enabled=enabled, severity=severity)

    def run(self):
        print("analysing view  %s " % self.current_view_name)
        self.entries.append(Control.Entry(view=self.current_view_name, details=" s => z"))
        # self.current_view_name = ""
        # Stack.print_stack()
        view_call = next(Stack.get_func_call(self.current_view_name), None)
        print("View called at : %s " % view_call)
        #print(get_resolver(None).reverse_dict)


class IO_OP(Control):
    """
    Writing data in disk, may be a data disclosure
    """
    def run(self):
        print("analysing view  %s " % self.current_view_name)
        self.entries.append(Control.Entry(view=self.current_view_name, details=" s => z"))
        # self.current_view_name = ""
        #Stack.print_stack(file="tmp2")
        view_call = next(Stack.get_func_call(self.current_view_name), None)
        print("View called at : %s " % view_call)


# Adding controls to the available controls in the blackbox
Blackbox.controls = [
    VIEWS_INTRACALLS(enabled=True, severity=Blackbox.Severity.HIGH),
    IO_OP(enabled=False, severity=Blackbox.Severity.MEDIUM)
]