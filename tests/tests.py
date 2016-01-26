"""
tests
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
from django.test import TestCase
from django.test import Client


class FodtlmonMiddlewareTestCase(TestCase):

    def setUp(self):
        self.client = Client(HTTP_X_FORWARDED_PROTOCOL='https')

    def test(self):
        response = Client().get('/')
        self.assertTrue('VCLOCK' in response)
        self.assertEqual(response["VCLOCK"], "{true}")

