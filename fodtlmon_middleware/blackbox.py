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

from pycallgraph import PyCallGraph
from pycallgraph.output import Output, GraphvizOutput


class GraphCallOutput(Output):

    def __init__(self, **kwargs):
        Output.__init__(self, **kwargs)

    def sanity_check(self):
        return True

    def done(self):
        # source = self.generate()
        # self.debug(source)
        for edge in self.processor.edges():
            print("edge %s " % edge.name)

        for node in self.processor.nodes():
            print("Node %s " % node.name)

        for edge in self.processor.groups():
            print(edge)


class CallTracer:
    """
    Function/method decorator
    """
    def __init__(self):
        """
        If there are decorator arguments, the function
        to be decorated is not passed to the constructor!
        """
        pass

    def __call__(self, f):
        """
        If there are decorator arguments, __call__() is only called
        once, as part of the decoration process! You can only give
        it a single argument, which is the function object.
        """
        def wrapped(*args, **kargs):
            #########################
            # Performing the fx call
            #########################
            # self.print("=== Before calling %s%s%s" % (f.__name__, args, kargs))
            graphviz = GraphvizOutput(output_file='filter_none.png')
            with PyCallGraph(output=graphviz):
                fx_ret = f(*args, **kargs)
            # self.print("=== After calling %s%s%s" % (f.__name__, args, kargs))

            # Push event into monitor
            # self.mon.trace.push_event(Event(predicates))
            return fx_ret
        return wrapped


########################################################
# Blackbox / Controls
########################################################

class Control:
    class Entry:
        def __init__(self, timestamp=None):
            self.timestamp = datetime.now() if timestamp is None else timestamp

    def __init__(self):
        self.name = self.__class__.__name__
        self.enabled = False
        self.entries = []

    def enable(self):
        pass

    def run(self, request, view, args, kwargs):
        pass


class CALL_GRAPH(Control):

    def run(self, request, view, args, kwargs):
        if self.enabled:
            print("analysing view  %s " % view)
            self.entries.append(Control.Entry())


class IO_OP(Control):

    def run(self, request, view, args, kwargs):
        if self.enabled:
            print("analysing view  %s " % view)


class Blackbox:
    """
    Blackbox class that contains all available controls
    """
    controls = [CALL_GRAPH(), IO_OP()]

