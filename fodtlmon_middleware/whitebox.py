import inspect
import sys
from fodtlmon.fodtl.fodtlmon import *
from enum import Enum
from datetime import datetime


########################################################
# Monitors
########################################################
class Monitor:
    """
    Generic monitor
    """
    def __init__(self, name="", description="", target="", location="LOCAL", kind=None, formula=None, debug=False, povo=True):
        self.id = name
        self.name = name
        self.target = target
        self.location = location
        self.description = description
        self.kind = kind
        self.formula = formula
        self.mon = Fotlmon(self.formula, Trace())
        self.debug = debug
        self.povo = povo
        self.enabled = True


class mon_fx(Monitor):
    """
    Function/method decorator
    """
    def __init__(self, formula=None, debug=False, povo=True):
        """
        If there are decorator arguments, the function
        to be decorated is not passed to the constructor!
        """
        super().__init__(formula, debug=debug, povo=povo)
        self.sig = None

    def print(self, *args):
        if self.debug:
            print(*args)

    def __call__(self, f):
        """
        If there are decorator arguments, __call__() is only called
        once, as part of the decoration process! You can only give
        it a single argument, which is the function object.
        """
        if inspect.isfunction(f):
            self.sig = inspect.signature(f)
        else:
            raise Exception("Unsupported type %s " % type(f))

        def wrapped(*args, **kargs):
            context = {}
            i = 0
            for p in self.sig.parameters:
                if i < len(args):
                    # Handle positional args first
                    context[str(p)] = args[i]
                else:
                    # Handle positional kargs first
                    context[str(p)] = kargs.get(str(p))
                i += 1

            # self.print("Call context : %s \n Decorator arguments : %s" % (context, self.formula))

            #########################
            # Performing the fx call
            #########################
            # self.print("=== Before calling %s%s%s" % (f.__name__, args, kargs))
            fx_ret = f(*args, **kargs)
            # self.print("=== After calling %s%s%s" % (f.__name__, args, kargs))

            #################
            # Pushing events
            #################
            predicates = []
            # Method call
            args2 = ["'"+str(args[0].__class__.__name__)+"'"] + ["'"+str(x)+"'" for x in args[1:]]
            args2 = ",".join(args2)
            predicates.append(Predicate(f.__name__, [Constant(args2)]))

            # Method arguments types / values
            for x in context:
                # predicates.append(Predicate(type(context.get(x)).__name__, [Constant(x)]))
                predicates.append(Predicate("ARG", [Constant(x)]))

                # Adding super types
                o = context.get(x)
                if isinstance(o, object):
                    for t in o.__class__.__mro__:
                        predicates.append(Predicate(t.__name__, [Constant(x)]))

            # Method return type / value
            # predicates.append(Predicate(type(fx_ret).__name__, [Constant(fx_ret)]))
            predicates.append(Predicate("RET", [Constant(fx_ret)]))

            if isinstance(fx_ret, object):
                for t in fx_ret.__class__.__mro__:
                    predicates.append(Predicate(t.__name__, [Constant(fx_ret)]))

            # Push event into monitor
            self.mon.trace.push_event(Event(predicates))

            # Run monitor
            # self.print(self.mon.trace)
            res = self.mon.monitor(once=False)

            if self.povo:
                print(res)

            # self.print(self.mon.formula.toCODE())
            return fx_ret
        return wrapped


########################################################
# Sysmon
########################################################
class Sysmon:
    """
    The main system that contains all submonitors
    """
    fx_monitors = []
    http_monitors = []

    class MonType(Enum):
        GENERIC = 0,
        HTTP = 1,
        FX = 2,

    def __init__(self):
        pass

    @staticmethod
    def register_mon(name, formula, target, location, kind, description):
        """
        Register a monitor
        :param name:
        :param formula:
        :param target:
        :param location:
        :param kind:
        :param description:
        :return:
        """
        pass

    @staticmethod
    def get_mon_by_id(id):
        return next(filter(lambda x: x.id == id, Sysmon.http_monitors + Sysmon.fx_monitors), None)

    @staticmethod
    def add_http_rule(name, formula, description=""):
        print("Adding http rule %s" % name)
        mon = Monitor(name=name, target="HTTP", location="LOCAL", kind=Sysmon.MonType.HTTP, formula=formula,
                      description=description, debug=False, povo=True)
        Sysmon.http_monitors.append(mon)

    @staticmethod
    def monitor_http_rules():
        for m in Sysmon.http_monitors:
            if m.enabled:
                e = Event.parse("{P(a)}")
                e.step = datetime.now()
                m.mon.trace.push_event(e)
                res = m.mon.monitor(once=True)
                print(res)
