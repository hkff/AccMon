import inspect
import sys
from fodtlmon.fodtl.fodtlmon import *
from enum import Enum
from datetime import datetime
import time
from fodtlmon_middleware.models import *
import socket

try:
    HOSTNAME = socket.gethostname()
except:
    HOSTNAME = 'localhost'


########################################################
# Monitors
########################################################
class Monitor:
    """
    Generic monitor
    """
    class MonType(Enum):
        GENERIC = 0,
        HTTP = 1,
        FX = 2,
        REMEDIATION = 3,
        VIEW = 4,
        RESPONSE = 5
    
    class MonControlType(Enum):
        POSTERIORI = 0,
        REAL_TIME = 1

    def __init__(self, name="", description="", target=None, location="LOCAL", kind=None,
                 control_type=MonControlType.POSTERIORI,
                 formula=None, debug=False, povo=True, violation_formula=None, liveness=None):
        """
        Init method
        :param name: The name of the monitor (for now the name is also the id)
        :param description:
        :param target:
        :param location: Monitor location (LOCAL / REMOTE_addr)
        :param kind: see Monitor.MonType
        :param formula: The FODTL formula to be monitored
        :param debug:
        :param povo: Print the result to sys out
        :param violation_formula: The formula to monitor when a remediation is triggered
        :param liveness: Livness delay :
        :return:
        """
        self.id = name
        self.name = name
        self.target = target
        self.location = location
        self.description = description
        self.kind = Monitor.MonType.GENERIC if kind is None else kind  # DO NOT use default value for karg
        self.formula = formula
        self.mon = Fodtlmon(self.formula, Sysmon.main_mon.trace)
        self.debug = debug
        self.povo = povo
        self.enabled = True
        self.control_type = control_type
        self.violations = []
        self.audits = []
        self.violation_formula = violation_formula
        self.liveness = liveness
        self.liveness_counter = liveness
        self.kv_implementation = KVector
        self.handle_remote_formulas()

    def handle_remote_formulas(self):
        """
        Handling remote formulas
        :return:
        """
        # 1. Create the Knowledge vector
        # kv = self.kv_implementation()

        # 2. Get all remote formulas
        remotes = self.mon.formula.walk(filter_type=At)

        # 3. Compute formulas hash
        for f in remotes:
            f.compute_hash(sid=self.id)
            Sysmon.main_mon.KV.add_entry(self.kv_implementation.Entry(f.fid, agent=self.name, value=Boolean3.Unknown, timestamp=0))
            sysactor = Sysmon.get_actor_by_name(f.agent)
            sysactor.formulas.append(f.inner)

        # IMPORTANT
        self.mon.reset()

        # 4. Add the knowledge vector
        self.mon.KV = Sysmon.main_mon.KV

    def monitor(self):
        """
        Monitoring method
        :return:
        """
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

        if self.kind is Monitor.MonType.REMEDIATION and res.get("result") is Boolean3.Top:
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
            mon = Monitor(name="%s_violation_%s" % (v.monitor_id, v.step),
                          target=self.target,
                          location=self.location,
                          kind=Monitor.MonType.REMEDIATION,
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


class Mon_http(Monitor):
    pass


class Mon_fx(Monitor):
    """
    Function/method decorator
    """
    def __init__(self, formula=None, debug=False, povo=True):
        """
        If there are decorator arguments, the function
        to be decorated is not passed to the constructor!
        """
        super().__init__(name="name", target="HTTP", location="LOCAL", kind=Monitor.MonType.FX, formula=formula,
                      description="", debug=False, povo=True, violation_formula=None, liveness=None)
        self.sig = None
        Sysmon.add_fx_mon(self)


    def print(self, *args):
        if self.debug:
            print(*args)

    def __call__(self, f):
        """
        If there are decorator arguments, __call__() is only called
        once, as part of the decoration process! You can only give
        it a single argument, which is the function object.
        """
        print("calling ........")
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
            # res = self.mon.monitor(once=False)
            self.monitor()
            # if self.povo:
            #     print(res)

            # self.print(self.mon.formula.toCODE())
            return fx_ret
        return wrapped


########################################################
# Sysmon
########################################################
class LogAttribute:
    """

    """
    def __init__(self, name, eval_fx=None, description="", enabled=True):
        self.name = name
        self.description = description
        self.eval_fx = eval_fx
        self.enabled = enabled


class Sysmon:
    """
    The main system that contains all submonitors
    """
    fx_monitors = []
    http_monitors = []
    views_monitors = []
    response_monitors = []
    main_mon = Fodtlmon("true", Trace())
    kv_implementation = KVector
    main_mon.KV = kv_implementation()
    actors = []

    class LogAttributes:
        """
        Log attributes list
        """
        SCHEME = LogAttribute("SCHEME", description="HTTP request schema.", enabled=True,
                              eval_fx=lambda request, view, args, kwargs, response:
                              P("SCHEME", args=[Constant(request.scheme)]))

        PATH = LogAttribute("PATH", description="", enabled=True, # IMPORTANT Parse path as regexp TODO for META also
                            eval_fx=lambda request, view, args, kwargs, response:
                            P(request.method, args=[Constant('"%s"' % request.path)]))

        USER = LogAttribute("USER", description="HTTP logged user id.", enabled=True,
                              eval_fx=lambda request, view, args, kwargs, response:
                              P("USER", args=[Constant(request.user)]))

        REMOTE_ADDR = LogAttribute("REMOTE_ADDR", description="Client ip adresse.", enabled=True,
                              eval_fx=lambda request, view, args, kwargs, response:
                              P("REMOTE_ADDR", args=[Constant(str(request.META.get("REMOTE_ADDR")))]))

        CONTENT_TYPE = LogAttribute("CONTENT_TYPE", description="Client ip adresse.", enabled=True,
                              eval_fx=lambda request, view, args, kwargs, response:
                              P("CONTENT_TYPE", args=[Constant(str(request.META.get("CONTENT_TYPE")))]))

        QUERY_STRING = LogAttribute("QUERY_STRING", description="Client ip adresse.", enabled=True,
                              eval_fx=lambda request, view, args, kwargs, response:
                              P("QUERY_STRING", args=[Constant(str(request.META.get("QUERY_STRING")))]))

    LGA = LogAttributes

    # Log attributes lists
    log_http_attributes = [LGA.SCHEME, LGA.PATH, LGA.USER, LGA.REMOTE_ADDR, LGA.CONTENT_TYPE, LGA.QUERY_STRING]
    log_view_attributes = []
    log_response_attributes = []

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
        return next(filter(lambda x: x.id == mon_id, Sysmon.get_mons()), None)

    @staticmethod
    def get_rule_by_name(rule_name, kind: Monitor.MonType) -> LogAttribute:
        rules = []
        if kind is Monitor.MonType.HTTP:
            rules = Sysmon.log_http_attributes
        elif kind is Monitor.MonType.VIEW:
            rules = Sysmon.log_view_attributes
        elif kind is Monitor.MonType.RESPONSE:
            rules = Sysmon.log_response_attributes
        return next(filter(lambda x: x.name == rule_name, rules), None)

    @staticmethod
    def add_fx_mon(mon):
        Sysmon.fx_monitors.append(mon)

    @staticmethod
    def add_http_rule(name: str, formula: str, description: str="", violation_formula: str=None, liveness: int=None,
                      control_type=Monitor.MonControlType.POSTERIORI):
        print("Adding http rule %s" % name)
        mon = Mon_http(name=name, target=Monitor.MonType.HTTP, location="LOCAL", kind=Monitor.MonType.HTTP,
                       formula=formula, description=description, debug=False, povo=True,
                       violation_formula=violation_formula, liveness=liveness, control_type=control_type)
        Sysmon.http_monitors.append(mon)

    @staticmethod
    def add_view_rule(name: str, formula: str, description: str="", violation_formula: str=None, liveness: int=None,
                      control_type=Monitor.MonControlType.POSTERIORI):
        print("Adding view rule %s" % name)
        mon = Mon_http(name=name, target=Monitor.MonType.VIEW, location="LOCAL", kind=Monitor.MonType.HTTP,
                       formula=formula, description=description, debug=False, povo=True,
                       violation_formula=violation_formula, liveness=liveness, control_type=control_type)
        Sysmon.views_monitors.append(mon)

    @staticmethod
    def add_response_rule(name: str, formula: str, description: str="", violation_formula: str=None, liveness: int=None,
                      control_type=Monitor.MonControlType.POSTERIORI):
        print("Adding response rule %s" % name)
        mon = Mon_http(name=name, target=Monitor.MonType.RESPONSE, location="LOCAL", kind=Monitor.MonType.HTTP,
                       formula=formula, description=description, debug=False, povo=True,
                       violation_formula=violation_formula, liveness=liveness, control_type=control_type)
        Sysmon.response_monitors.append(mon)

    @staticmethod
    def push_event(e: Event):
        # Push the event to the main mon
        Sysmon.main_mon.trace.push_event(e)
        # Store the event into the db
        pass

    @staticmethod
    def get_mons():
        return Sysmon.fx_monitors + Sysmon.http_monitors + Sysmon.views_monitors + Sysmon.response_monitors

    @staticmethod
    def audit(mon_id, violation_id, comment, verdict):
        m = Sysmon.get_mon_by_id(mon_id)
        if m is not None:
            v = next(filter(lambda x: x.vid == violation_id, m.violations))
            if v is not None:
                v.audit = comment
                v.verdict = verdict
                m.audits.append(violation_id)

    @staticmethod
    def register_actor(name, addr):
        addr = addr.split(":")  # TODO check and secure
        a = Actor(name, addr[0], addr[1])
        Sysmon.actors.append(a)

    @staticmethod
    def get_actor_by_name(name):
        return next(filter(lambda x: x.name == name, Sysmon.actors), None)

    @staticmethod
    def add_log_attribute(attr: LogAttribute, target=Monitor.MonType.HTTP):
        setattr(Sysmon.LogAttributes, attr.name, attr)
        if target is Monitor.MonType.HTTP:
            Sysmon.log_http_attributes.append(attr)
        elif target is Monitor.MonType.VIEW:
            Sysmon.log_view_attributes.append(attr)
        elif target is Monitor.MonType.RESPONSE:
            Sysmon.log_response_attributes.append(attr)
        else:
            raise Exception("Please specify a target for your rule Monitor.MonType.(HTTP/VIEW/RESPONSE/)")

    # TODO add initsysmon to perform some checks
    # example : check if all predicates in formula can be logged
    # safe /unsafe agents
