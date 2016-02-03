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
        c_func = frame.f_code.co_name
        c_file = frame.f_code.co_filename
        c_lineinfo = frame.f_lineno
        c_class = frame.f_locals['self'].__class__.__name__ if 'self' in frame.f_locals else ''
        c_module = frame.f_locals['self'].__class__.__module__ if 'self' in frame.f_locals else ''
        return {"event": -1, "c_func": c_func, "c_file": c_file, "c_lineinfo": c_lineinfo,
                "c_class": c_class, "c_c_module": c_module, "parent": None}

    @staticmethod
    def print_stack():
        for x in Stack.frames:
            p = '' if x.get("parent") is None else x.get("parent").get("c_func")
            print("%s %s %s" % (x.get("event").name, x.get("c_func"), p))


def view_tracer(frame, event, arg):
    """
    Python tracer
    :param frame:
    :param event:
    :param arg:
    :return:
    """
    try:
        # Parent frame details
        p_frame = None if frame.f_back is None else Stack.frame_to_dict(frame.f_back)

        # Current frame details
        c_frame = Stack.frame_to_dict(frame.f_back)
        c_frame['parent'] = p_frame

        if event == 'call':
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
        def __init__(self, timestamp=None):
            self.timestamp = datetime.now() if timestamp is None else timestamp

    def __init__(self, enabled=False, severity=None):
        self.name = self.__class__.__name__
        self.enabled = enabled
        self.severity = Blackbox.Severity.UNDEFINED if severity is None else severity
        self.entries = []
        self.current_view_name = ""

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

    def run(self):
        print("analysing view  %s " % self.current_view_name)
        self.entries.append(Control.Entry())
        self.current_view_name = ""
        # Stack.print_stack()


class IO_OP(Control):
    pass


# Adding controls to the available controls in the blackbox
Blackbox.controls = [VIEWS_INTRACALLS(enabled=True)]
