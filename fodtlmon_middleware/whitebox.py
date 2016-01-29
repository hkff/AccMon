import inspect
import sys
from fodtlmon.fodtl.fodtlmon import *
from enum import Enum
from datetime import datetime
import time
from fodtlmon_middleware.models import *


########################################################
# Monitors
########################################################
class Monitor:
    """
    Generic monitor
    """
    def __init__(self, name="", description="", target="", location="LOCAL", kind=None,
                 formula=None, debug=False, povo=True, violation_formula=None, liveness=None):
        """
        Init method
        :param name: The name of the monitor (for now the name is also the id)
        :param description:
        :param target:
        :param location: Monitor location (LOCAL / REMOTE_addr)
        :param kind: see Sysmon.MonType
        :param formula: The FODTL formula to be monitored
        :param debug:
        :param povo: Print the result to sys out
        :param violation_formula: The formula to monitor when a remediation is triggered
        :param livness: Livness delay :
        :return:
        """
        self.id = name
        self.name = name
        self.target = target
        self.location = location
        self.description = description
        self.kind = Sysmon.MonType.GENERIC if kind is None else kind  # DO NOT use default value for karg
        self.formula = formula
        self.mon = Fodtlmon(self.formula, Sysmon.main_mon.trace)
        self.debug = debug
        self.povo = povo
        self.enabled = True
        self.violations = []
        self.audits = []
        self.violation_formula = violation_formula
        self.liveness = liveness
        self.liveness_counter = liveness

    def monitor(self):
        res = self.mon.monitor(once=True, struct_res=True)

        if res.get("result") is Boolean3.Bottom:
            self.mon.last = Boolean3.Unknown
            self.mon.reset()
            v = Violation(self.id, step=self.mon.counter, trace=self.mon.trace.events[self.mon.counter-1])
            self.violations.append(v)

        elif res.get("result") is Boolean3.Unknown:
            # test liveness
            if self.liveness is not None:
                if isinstance(self.mon.formula, Always):  # Test if it's a liveness formula
                    # Check the rewrite formula
                    if isinstance(self.mon.rewrite, And):  # Bad prefix
                        self.liveness_counter -= 1
                    elif isinstance(self.mon.rewrite, Always):  # Good prefix
                        self.liveness_counter = self.liveness

        if self.kind is Sysmon.MonType.REMEDIATION and res.get("result") is Boolean3.Top:
            # Disable monitor
            self.enabled = False

        print(res)
        return res

    def reset(self):
        self.mon.last = Boolean3.Unknown
        self.mon.reset()

    def audit(self):
        pass

    def get_violation_by_id(self, vid) -> Violation:
        return next(filter(lambda x: x.vid == vid, self.violations), None)

    def trigger_remediation(self, violation_id):
        v = self.get_violation_by_id(violation_id)
        if v is not None:
            mon = Monitor(name="%s_violation@%s" % (v.monitor_id, v.step),
                          target=self.target,
                          location=self.location,
                          kind=Sysmon.MonType.REMEDIATION,
                          formula=self.violation_formula,
                          description="Remediation monitor for monitor %s" % self.name,
                          debug=False,
                          povo=True,
                          violation_formula=None)

            # IMPORTANT : stat remediation monitoring after the violation occurs
            mon.mon.counter = int(v.step)
            mon.mon.counter2 = int(v.step)
            v.remediation_mon = mon
            Sysmon.http_monitors.append(mon)

    def is_liveness_expired(self):
        if self.liveness is not None:
            res = self.liveness_counter <= 0
            return abs(self.liveness_counter) if res else False
        return False


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
    main_mon = Fodtlmon("true", Trace())

    class MonType(Enum):
        GENERIC = 0,
        HTTP = 1,
        FX = 2,
        REMEDIATION = 3

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
    def get_mon_by_id(mon_id) -> Monitor:
        return next(filter(lambda x: x.id == mon_id, Sysmon.http_monitors + Sysmon.fx_monitors), None)

    @staticmethod
    def add_http_rule(name, formula, description="", violation_formula=None, liveness=None):
        print("Adding http rule %s" % name)
        mon = Monitor(name=name, target="HTTP", location="LOCAL", kind=Sysmon.MonType.HTTP, formula=formula,
                      description=description, debug=False, povo=True, violation_formula=violation_formula, liveness=liveness)
        Sysmon.http_monitors.append(mon)

    @staticmethod
    def monitor_http_rules():
        for m in Sysmon.http_monitors:
            if m.enabled:
                res = m.monitor()
                # TODO : automatic audit after x mn ??
                print(res)

    @staticmethod
    def push_event(e):
        # Push the event to the main mon
        Sysmon.main_mon.trace.push_event(e)
        # Store the event into the db
        pass

    @staticmethod
    def get_mons():
        return Sysmon.fx_monitors + Sysmon.http_monitors

    @staticmethod
    def audit(mon_id, violation_id, comment, verdict):
        m = Sysmon.get_mon_by_id(mon_id)
        if m is not None:
            v = next(filter(lambda x: x.vid == violation_id, m.violations))
            if v is not None:
                v.audit = comment
                v.verdict = verdict
                m.audits.append(violation_id)

