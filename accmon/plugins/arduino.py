"""
Arduino plugin
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
import threading
from time import sleep
import serial
from accmon.plugins.plugin import *
import glob


class Arduino(Plugin):

    def __init__(self):
        super().__init__()
        self.connector = None

    def handle_request(self, request):
        res = super(Arduino, self).handle_request(request)
        if res is not None: return res

    def get_template_args(self):
        super_args = super(Arduino, self).get_template_args()
        ttys = glob.glob('/dev/tty*')
        args = {"ttys": ttys}
        args.update(super_args)
        return args

    def start_arduino(self):
        ser = serial.Serial('/dev/ttyUSB0', 9600)
        while True:
            res = str(ser.readline().decode("utf-8"))
            if res != "":
                self.main_mon.push_event(Event([Predicate("%s" % res)], step=datetime.now()))
                for x in self.monitors:
                    x.monitor()
            sleep(1)

    def connect(self):
        self.connector = threading.Thread(target=self.start_arduino)
        self.connector.start()
