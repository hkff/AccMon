"""
Plugin
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
from fodtlmon_middleware.sysmon import *


class Plugin:
    """
    Plugin
    """
    def __init__(self):
        self.name = self.__class__.__name__
        self.monitors = []
        self.enabled = False

    def get_template_args(self):
        return {}

    def handle_request(self, request):
        pass
