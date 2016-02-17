"""
django-fodtlmon-middleware version 1.0
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
from distutils.core import setup

setup(
    name='django-fodtlmon-middleware',
    version='1.0',
    packages=['fodtlmon_middleware'],
    package_data={
        'fodtlmon_middleware': [
            'static/*', 'static/css/*', 'static/js/*', 'static/fonts/*',
            'templates/*', 'templates/pages/*', 'templates/fragments/*'
        ]},
    url='https://github.com/hkff/django-fodtlmon-middleware',
    license='GPL3',
    author='Walid Benghabrit',
    author_email='Walid.Benghabrit@mines-nantes.fr',
    description='FODTLMON-middleware is a monitoring middleware for django.',
    install_requires=[
        'fodtlmon>=1.0',
        'pyserial>=3.0'
    ]
)
