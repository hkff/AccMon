"""
Logging
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
from fodtlmon.fodtl.fodtlmon import *


class LogAttribute:
    """

    """
    def __init__(self, name, eval_fx=None, description="", enabled=True):
        self.name = name
        self.description = description
        self.eval_fx = eval_fx
        self.enabled = enabled


class LogAttributes:
    """
    Log attributes list
    """
    SCHEME = LogAttribute("SCHEME", description="The scheme of the request (http or https usually).", enabled=True,
                          eval_fx=lambda request, view, args, kwargs, response:
                          P("SCHEME", args=[Constant(request.scheme)]))

    PATH = LogAttribute("PATH", description="The full path to the requested page, not including the scheme or domain.",
                        enabled=True, # IMPORTANT Parse path as regexp TODO for META also
                        eval_fx=lambda request, view, args, kwargs, response:
                        P(request.method, args=[Constant('"%s"' % request.path)]))

    USER = LogAttribute("USER", description="The currently logged-in user.", enabled=True,
                          eval_fx=lambda request, view, args, kwargs, response:
                          P("USER", args=[Constant(request.user)]))

    REMOTE_ADDR = LogAttribute("REMOTE_ADDR", description="The IP address of the client.", enabled=True,
                          eval_fx=lambda request, view, args, kwargs, response:
                          P("REMOTE_ADDR", args=[Constant(str(request.META.get("REMOTE_ADDR")))]))

    CONTENT_TYPE = LogAttribute("CONTENT_TYPE", description="The MIME type of the request body.", enabled=True,
                          eval_fx=lambda request, view, args, kwargs, response:
                          P("CONTENT_TYPE", args=[Constant(str(request.META.get("CONTENT_TYPE")))]))

    QUERY_STRING = LogAttribute("QUERY_STRING", description=" The query string, as a single (unparsed) string.", enabled=True,
                          eval_fx=lambda request, view, args, kwargs, response:
                          P("QUERY_STRING", args=[Constant(str(request.META.get("QUERY_STRING")))]))

    # View specific
    VIEW_NAME = LogAttribute("VIEW_NAME", description=" The current called django view.", enabled=True,
                          eval_fx=lambda request, view, args, kwargs, response:
                          P("VIEW", args=[Constant(str(view.__name__))]))

    # Response specific
    STATUS_CODE = LogAttribute("STATUS_CODE", description=" The HTTP status code for the response.", enabled=True,
                          eval_fx=lambda request, view, args, kwargs, response:
                          P("STATUS_CODE", args=[Constant(str(response.status_code))]))

LGA = LogAttributes
