[![License](https://img.shields.io/badge/version-1.1-orange.svg)]()
[![License](https://img.shields.io/badge/license-GPL3-blue.svg)]()
[![License](https://img.shields.io/badge/python->%3D3.4-green.svg)]()

# AccMon
AccMon Version 1.1

What is it?
-----------

AccMon is a monitoring middleware for django, using FodtlMon a monitor based on distributed first order linear temporal logic. It allows to monitor formula defined on HTTP traffic, views processing and external tools via plugins.
Note that this framework is a research prototype and should not be used in production !

Installation
------------

You can install accmon directly using pip3 :

    https://pypi.python.org/pypi/accmon
    $ sudo pip3 install accmon
    
You need PythonX.X.X >= Python3.4.0 installed on your system

    You need to install the following dependencies :  
            $ sudo pip3 install fodtlmon
            $ sudo python3 setup.py install

Usage
-----

1. In your django project settings.py :
    add the following app 'accmon' to INSTALLED_APPS 
    add 'accmon.middleware.FodtlmonMiddleware' in the MIDDLEWARE_CLASSES

2. In your django project wsgi.py :
    add the init call to the monitoring system
    
        from accmon.sysmon import Sysmon
        Sysmon.init()


2. Create a python file (eg.: sysmon_rules.py)
    Note that the code above should be executed only once when the server starts
        
        from accmon.sysmon import *
        
        # Define your Interpreted predicates here
        
        # Add your http request rules here
        Sysmon.add_http_rule(<monitor_name>, <formula_to_monitor>, args...)

        # Add your view rules here
        Sysmon.add_view_rule(<monitor_name>, <formula_to_monitor>, args...)
        
        # Add your response rules here
        Sysmon.add_response_rule(<monitor_name>, <formula_to_monitor>, args...)

    where args are the following optional arguments  :
    
        description="", violation_formula: str=None, liveness=None, control_type=Monitor.MonControlType.POSTERIORI | REAL_TIME
                      
3. Add the import of sysmon_rules in your wsgi.py

4. In urls.py :
    Add the following import
        
        from accmon import urls as fodtlurls

    and the url pattern :
        (eg.: here the system monitor app will be accessed via http../your_base_url/mon)
        
        url(r'^mon/', include(fodtlurls.urlpatterns)),

5. Optional : 
    You can also define monitors on functions and class methods using the decorator @mon_fx
         

6. Now your are ready !


Licensing
---------

GPL V3 . Please see the file called LICENSE.

Contacts
--------

###### Developer :
>   Walid Benghabrit        <Walid.Benghabrit@mines-nantes.fr>

###### Contributors :
>   Pr.Jean-Claude Royer  <Jean-Claude.Royer@mines-nantes.fr>  (Theory)  
>   Dr. Hervé Grall       <Herve.Grall@mines-nantes.fr>        (Theory)  

-------------------------------------------------------------------------------
Copyright (C) 2014-2016 Walid Benghabrit  
Ecole des Mines de Nantes - ARMINES  
ASCOLA Research Group  
A4CLOUD Project http://www.a4cloud.eu/

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
