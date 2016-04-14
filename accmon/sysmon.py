"""
sysmon
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
import inspect
import sys
from accmon.logging import *
from django.http.response import HttpResponseBase
from fodtlmon.fodtl.fodtlmon import *
from enum import Enum
from datetime import datetime
import time
from accmon.blackbox import *
# from django.http import HttpResponse
from django.conf import settings
from django.core.urlresolvers import RegexURLResolver, RegexURLPattern, get_resolver
from accmon.models import *
import socket
import urllib.request
import urllib.parse

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
        """
        Contains different monitors types :
            GENERIC     : a generic monitor (not used)
            HTTP        : monitoring is performed when receving an HTTP request
            FX          : monitoring is performed on a python function/method
            REMEDIATION : a remediation monitor
            VIEW        : monitoring is performed on view processing
            RESPONSE    : monitoring is performed on response
        """
        GENERIC = 0,
        HTTP = 1,
        FX = 2,
        REMEDIATION = 3,
        VIEW = 4,
        RESPONSE = 5

    class MonControlType(Enum):
        """
        Monitor control types, we have two types of controls :
            POSTERIORI : The monitor's run is not blocking
            REAL_TIME  : The monitor's run is blocking, and if a violation occurs
        """
        POSTERIORI = 0,
        REAL_TIME = 1

    def __init__(self, name="", description="", target=None, location="LOCAL", kind=None,
                 control_type=MonControlType.POSTERIORI, formula=None, debug=False, povo=True, violation_formula=None,
                 liveness=None, mon_trace=None):
        """
        Init method
        :param name: The name of the monitor (for now the name is also the id)
        :param description: a short description of what the monitor does
        :param target:
        :param location: Monitor location (LOCAL / REMOTE_addr)
        :param kind: see Monitor.MonType
        :param formula: The FODTL formula to be monitored
        :param debug:
        :param povo: Print the result to sys out
        :param violation_formula: The formula to monitor when a remediation is triggered
        :param liveness:
        :return:
        """
        self.id = name
        self.name = name
        self.target = target
        self.location = location
        self.description = description
        self.kind = Monitor.MonType.GENERIC if kind is None else kind  # DO NOT use default value for karg
        self.formula = formula
        self.mon = Fodtlmon(self.formula, mon_trace)
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
        # Get all remote formulas
        remotes = self.mon.formula.walk(filter_type=At)

        # Compute formulas hash
        for f in remotes:
            f.compute_hash(sid=self.id)
            Sysmon.main_mon.KV.add_entry(self.kv_implementation.Entry(f.fid, agent=self.name, value=Boolean3.Unknown, timestamp=0))
            sysactor = Sysmon.get_actor_by_name(f.agent)
            if sysactor is not None:
                sysactor.formulas.append(f)

        # IMPORTANT
        self.mon.reset()

        # Add the knowledge vector
        self.mon.KV = Sysmon.main_mon.KV

    def monitor(self):
        """
        Trigger the monitor
        - If the result is ⊥ then the monitor status is changed to ? and a violation is created.
        - If the result is ? and the liveness parameter is given and the formula is a liveness formula :
            * The liveness counter is decremented if the monitor is in a good prefix.
            * The liveness counter is rested if the monitor is in a bad prefix.
        - If the result is ⊤ and the monitor's kind is remediation then the monitor is disabled.
        :return:
        """
        res = self.mon.monitor(once=True, struct_res=True)
        if res.get("result") is Boolean3.Bottom:
            # Only G(...) formulas can be violated multiple time, other formula are violated once
            if len(self.violations) == 0 or isinstance(self.mon.formula, Always):
                v = Violation(self.id, step=self.mon.counter, trace=self.mon.trace.events[self.mon.counter-1])
                self.violations.append(v)
            # Reset only if it's a formula G(...)
            if isinstance(self.mon.formula, Always):
                self.mon.last = Boolean3.Unknown
                self.mon.reset()

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

        # Update KV
        if self.location != "LOCAL":
            agent = self.id.split("@")[0].strip()
            self.mon.KV.update(IKVector.Entry(self.id, agent=agent, value=res.get("result"), timestamp=self.mon.counter))

        print(res)
        return res

    def reset(self):
        """
        Reset the monitor formula and set the last result to ? .
        Note that the current monitor step is not reinitialized.
        :return:
        """
        self.mon.last = Boolean3.Unknown
        self.mon.reset()

    def audit(self):
        pass

    def get_violation_by_id(self, vid) -> Violation:
        """
        Returns the violation of the corresponding id if exists else None
        :param vid:
        :return:
        """
        return next(filter(lambda x: x.vid == vid, self.violations), None)

    def trigger_remediation(self, violation_id):
        """
        Trigger a remediation for the corresponding violation
        :param violation_id:
        :return:
        """
        if self.violation_formula is None:
            return
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
                          violation_formula=None,
                          mon_trace=self.target)

            # IMPORTANT : start remediation monitoring after the violation occurs
            mon.mon.counter = int(v.step)
            mon.mon.counter2 = int(v.step)
            v.remediation_mon = mon
            Sysmon.http_monitors.append(mon)

    def is_liveness_expired(self) -> bool:
        """
        Compare the current liveness counter with the base liveness
        :return: Boolean
        """
        if self.liveness is not None:
            res = self.liveness_counter <= 0
            return abs(self.liveness_counter) if res else False
        return False


class Mon_http(Monitor):
    pass


class Mon_view(Monitor):
    pass


class Mon_response(Monitor):
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
class Sysmon:
    """
    The main system that contains all submonitors
        fx_monitors
        http_monitors
        views_monitors
        response_monitors
        main_mon
        main_view_mon
        main_response_mon
        kv_implementation
        main_mon.KV
        main_view_mon.KV
        main_response_mon.KV
        actors
        log_http_attributes
        log_view_attributes
        log_response_attributes
    """
    fx_monitors = []
    http_monitors = []
    views_monitors = []
    response_monitors = []
    main_mon = Fodtlmon("true", Trace())
    main_view_mon = Fodtlmon("true", Trace())
    main_response_mon = Fodtlmon("true", Trace())
    kv_implementation = KVector
    main_mon.KV = kv_implementation()
    main_view_mon.KV = kv_implementation()
    main_response_mon.KV = kv_implementation()
    actors = []
    plugins = []

    # Log attributes lists
    log_http_attributes = [
        LGA.SCHEME, LGA.PATH, LGA.USER, LGA.REMOTE_ADDR, LGA.CONTENT_TYPE, LGA.QUERY_STRING, LGA.REAL_IP,
        LGA.USER_AGENT, LGA.ADMIN, LGA.SESSION
    ]
    log_view_attributes = [LGA.VIEW_NAME]
    log_response_attributes = [LGA.STATUS_CODE]

    @staticmethod
    def init():
        """
        Initialize the sysmon
        this method should be called after the server starts
        :return:
        """
        Blackbox.VIEWS = [x.__name__ for x in list(filter(lambda y: inspect.isfunction(y), get_resolver(None).reverse_dict))]
        Blackbox.INSTALLED_APPS = settings.INSTALLED_APPS
        Blackbox.MIDDLEWARE_CLASSES = settings.MIDDLEWARE_CLASSES
        HttpResponseBase.__init__ = HttpResponseBaseIntercepter(HttpResponseBase.__init__)
        for control in Blackbox.CONTROLS:
            control.initialize()

        # Import plugins
        from accmon.plugins import remote, system, arduino, sandbox, apache, assertionToolkit
        Sysmon.plugins = [remote.Remote(), system.System(), arduino.Arduino(), sandbox.Sandbox(), apache.Apache(),
                          assertionToolkit.AssertionToolkit()]

    @staticmethod
    def check_logged_predicates():
        active_attributes = [x.name for x in list(filter(lambda x: x.enabled, Sysmon.get_log_attributes()))]
        for mon in Sysmon.get_mons():
            predicates = mon.mon.formula.walk(filter_type=Predicate)
            for p in predicates:
                if p.name not in active_attributes:
                    print("Warning predicate %s may be not logged ! " % p.name)

    @staticmethod
    def get_log_attributes():
        return Sysmon.log_http_attributes + Sysmon.log_view_attributes + Sysmon.log_response_attributes

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
                      control_type=Monitor.MonControlType.POSTERIORI, location="LOCAL"):
        """

        :param name:
        :param formula:
        :param description:
        :param violation_formula:
        :param liveness:
        :param control_type:
        :return:
        """
        print("Adding http rule %s" % name)
        mon = Mon_http(name=name, target=Monitor.MonType.HTTP, location=location, kind=Monitor.MonType.HTTP,
                       formula=formula, description=description, debug=False, povo=True, mon_trace=Sysmon.main_mon.trace,
                       violation_formula=violation_formula, liveness=liveness, control_type=control_type)
        Sysmon.http_monitors.append(mon)

    @staticmethod
    def add_view_rule(name: str, formula: str, description: str="", violation_formula: str=None, liveness: int=None,
                      control_type=Monitor.MonControlType.POSTERIORI):
        """

        :param name:
        :param formula:
        :param description:
        :param violation_formula:
        :param liveness:
        :param control_type:
        :return:
        """
        print("Adding view rule %s" % name)
        mon = Mon_view(name=name, target=Monitor.MonType.VIEW, location="LOCAL", kind=Monitor.MonType.HTTP,
                       formula=formula, description=description, debug=False, povo=True, mon_trace=Sysmon.main_view_mon.trace,
                       violation_formula=violation_formula, liveness=liveness, control_type=control_type)
        Sysmon.views_monitors.append(mon)

    @staticmethod
    def add_response_rule(name: str, formula: str, description: str="", violation_formula: str=None, liveness: int=None,
                      control_type=Monitor.MonControlType.POSTERIORI):
        """

        :param name:
        :param formula:
        :param description:
        :param violation_formula:
        :param liveness:
        :param control_type:
        :return:
        """
        print("Adding response rule %s" % name)
        mon = Mon_response(name=name, target=Monitor.MonType.RESPONSE, location="LOCAL", kind=Monitor.MonType.HTTP,
                           formula=formula, description=description, debug=False, povo=True, mon_trace=Sysmon.main_response_mon.trace,
                           violation_formula=violation_formula, liveness=liveness, control_type=control_type)
        Sysmon.response_monitors.append(mon)

    @staticmethod
    def push_event(e: Event, target: Monitor.MonType):
        """
        Push an event into the corresponding main monitor (HTTP/VIEW/RESPONSE)
        :param e: the event
        :param target: the target (MonType.HTTP | MonType.VIEW | MonType.RESPONSE)
        :return:
        """
        # Push the event to the main mon
        if target is Monitor.MonType.HTTP:
            Sysmon.main_mon.trace.push_event(e)
        elif target is Monitor.MonType.VIEW:
            Sysmon.main_view_mon.trace.push_event(e)
        elif target is Monitor.MonType.RESPONSE:
            Sysmon.main_response_mon.trace.push_event(e)
        # Store the event into the db
        pass

    @staticmethod
    def get_mons():
        plugins = []
        for x in Sysmon.plugins:
            plugins.extend(x.monitors)
        return Sysmon.fx_monitors + Sysmon.http_monitors + Sysmon.views_monitors + Sysmon.response_monitors + plugins

    @staticmethod
    def audit(mon_id, violation_id, comment, verdict):
        """
        Performs an audit
        :param mon_id:
        :param violation_id:
        :param comment:
        :param verdict:
        :return:
        """
        m = Sysmon.get_mon_by_id(mon_id)
        if m is not None:
            v = next(filter(lambda x: x.vid == violation_id, m.violations))
            if v is not None:
                v.audit = comment
                v.verdict = verdict
                m.audits.append(violation_id)

    @staticmethod
    def register_actor(name, addr, port):
        """
        Register an actor
        :param name:
        :param addr:
        :param port:
        :return:
        """
        a = Actor(name, addr, port)
        Sysmon.actors.append(a)

    @staticmethod
    def get_actor_by_name(name):
        return next(filter(lambda x: x.name == name, Sysmon.actors), None)

    @staticmethod
    def get_blackbox_control_by_name(name):
        return next(filter(lambda x: x.name == name, Blackbox.CONTROLS), None)

    @staticmethod
    def add_log_attribute(attr: LogAttribute, target=Monitor.MonType.HTTP):
        """
        Adding a custom logging attribute
        :param attr: The LogAttribute to add
        :param target: the target (MonType.HTTP | MonType.VIEW | MonType.RESPONSE)
        :return:
        """
        setattr(LogAttributes, attr.name, attr)
        if target is Monitor.MonType.HTTP:
            Sysmon.log_http_attributes.append(attr)
        elif target is Monitor.MonType.VIEW:
            Sysmon.log_view_attributes.append(attr)
        elif target is Monitor.MonType.RESPONSE:
            Sysmon.log_response_attributes.append(attr)
        else:
            raise Exception("Please specify a target for your rule Monitor.MonType.(HTTP/VIEW/RESPONSE/)")

    @staticmethod
    def register_actor_formulas(actor_id):
        actor = Sysmon.get_actor_by_name(actor_id)
        if actor is not None:
            for formula in actor.formulas:
                data = {
                    "formula": formula.inner,
                    "formula_id": formula.fid,
                    "target": HOSTNAME,
                    "KV": Sysmon.main_mon.KV
                }
                data = urllib.parse.urlencode(data)
                data = data.encode('ascii')
                res = urllib.request.urlopen(actor.ip_addr + "/mon/sysmon/remote/register_formula/", data)  # FIXME
                kv = res.info().get('KV')
                # res.read().decode('utf-8'))
                if kv is not None:
                    Sysmon.main_mon.update_kv(Sysmon.kv_implementation.parse(kv))
                actor.status = Actor.ActorStatus.CONNECTED
