"""
accmon version 1.1
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
from setuptools import setup

setup(
    name='accmon',
    version='1.1',
    packages=['accmon', 'accmon/plugins'],
    package_data={
        'accmon': [
            'static/*.png', 'static/favicon.ico', 'static/css/*', 'static/js/*', 'static/fonts/*',
            'templates/*.html', 'templates/pages/*.html', 'templates/fragments/*.html', 'templates/fragments/plugins/*'
        ]},
    url='https://github.com/hkff/Accmon',
    license='GPL3',
    author='Walid Benghabrit',
    author_email='benghabrit.walid@gmail.com',
    description='Accmon is an accountability monitoring middleware for django.',
    install_requires=[
        'fodtlmon>=1.0',
        'pyserial>=3.0',
        'django>=1.8',
    ]
)
