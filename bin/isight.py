#!/usr/bin/env python

import httplib
import json
import hashlib
import hmac
import urllib
import urlparse
import datetime
import time
import calendar
import sys
import csv
import os.path


import random, sys

from splunklib.modularinput import *

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

class MyScript(Script):
    """All modular inputs should inherit from the abstract base class Script
    from splunklib.modularinput.script.
    They must override the get_scheme and stream_events functions, and,
    if the scheme returned by get_scheme has Scheme.use_external_validation
    set to True, the validate_input function.
    """
    def get_scheme(self):
        """When Splunk starts, it looks for all the modular inputs defined by
        its configuration, and tries to run them with the argument --scheme.
        Splunkd expects the modular inputs to print a description of the
        input in XML on stdout. The modular input framework takes care of all
        the details of formatting XML and printing it. The user need only
        override get_scheme and return a new Scheme object.

        :return: scheme, a Scheme object
        """
        # "ISIGHT" is the name Splunk will display to users for this input.
        scheme = Scheme("ISIGHT")

        scheme.description = "Retrieves threat data from http://www.isightpartners.com."
        # If you set external validation to True, without overriding validate_input,
        # the script will accept anything as valid. Generally you only need external
        # validation if there are relationships you must maintain among the
        # parameters, such as requiring min to be less than max in this example,
        # or you need to check that some resource is reachable or valid.
        # Otherwise, Splunk lets you specify a validation string for each argument
        # and will run validation internally using that string.
        scheme.use_external_validation = False
        scheme.use_single_instance = True

        pubkey_argument = Argument("PublicKey")
        pubkey_argument.data_type = Argument.data_type_string
        pubkey_argument.description = "The PublicKey associated with your isightpartners account."
        pubkey_argument.required_on_create = True
        # If you are not using external validation, you would add something like:
        #
        # scheme.validation = "min > 0"
        scheme.add_argument(pubkey_argument)

        privkey_argument = Argument("PrivateKey")
        privkey_argument.data_type = Argument.data_type_string
        privkey_argument.description = "The PrivateKey associated with your isightpartners account."
        privkey_argument.required_on_create = True
        scheme.add_argument(privkey_argument)

        return scheme



    def stream_events(self, inputs, ew):
        """This function handles all the action: splunk calls this modular input
        without arguments, streams XML describing the inputs to stdin, and waits
        for XML on stdout describing events.

        If you set use_single_instance to True on the scheme in get_scheme, it
        will pass all the instances of this input to a single instance of this
        script.

        :param inputs: an InputDefinition object
        :param ew: an EventWriter object
        """
        ew.log("DEBUG", "Started stream_events")

        def parseJsonAndPrint(url, path, query, pub, prv):
            data = getData(url, path, query, pub, prv);
            content = data[u'message']
            return(content)
 
        def getData(url, path, query, pub, prv):
            # Set the log level to DEBUG for the ExecProcessor log to see these messages
            ew.log("DEBUG", "Started getData")
            ew.log("DEBUG", "getData: url=" + url + " path=" + path + " query=" + query + " pub=" + pub + " prv=" + prv )
            hashed = hmac.new(prv, '', hashlib.sha256)
            headers = {'X-Auth' : pub, 'X-Auth-Hash' : hashed.hexdigest()}
            try:
                conn = httplib.HTTPSConnection(url)
            except:
                ew.log("ERROR", "getData: httplib.HTTPSConnection failed")
            conn.request('GET', path + '?' + query, '', headers)
            try:
                resp = conn.getresponse()
            except:
                ew.log("ERROR", "getData: conn.getresponse failed")
            
            #ew.log("DEBUG", "getData: resp=" + resp.read() )
            #try:
            jsondata = json.loads(resp.read())
            #except:
            #    ew.log("ERROR", "jsondata: The data returned was not json. type=" + type(resp.read()) + " data=" + resp.read())
            #ew.log("INFO", "getData: jsondata=" + jsondata[u'message'] )
            #print jsondata
            ew.log("DEBUG", "Ended getData")
            return jsondata

        #while True:
        
        # Go through each input for this modular input
        for input_name, input_item in inputs.inputs.iteritems():
            # Get the values, cast them as floats
            #ew.log("DEBUG", "Started input iteration: " + input_name)
            pub_key = input_item["PublicKey"]
            priv_key  = input_item["PrivateKey"]

            nowish = calendar.timegm(time.gmtime())
            backthenish = nowish
            tracker_filename=os.path.join(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'lookups'), 'time_tracker')

            if os.path.isfile(tracker_filename):
                pass
            else:
                try:
                    init_file = open(tracker_filename, 'wb')
                    init_file.close()
                except :
                    ew.log("ERROR", "Could not open file " + tracker_filename + " for writing.")

            
            try:
                alltimes = open(tracker_filename, 'r+b')
            except :
                ew.log("ERROR", "Could not open file " + tracker_filename + " for reading.")
            timelist = alltimes.readlines()
            if len(timelist) < 2:
                ew.log("DEBUG", "Timelist from file was less than 2")
                sincetime = calendar.timegm(time.gmtime()) - 86400*90
                alltimes.write(str(sincetime) + '\n')
                ew.log("DEBUG", "Wrote " + str(sincetime) + " to time_tracker")
                alltimes.write(str(nowish) + '\n')
                ew.log("DEBUG", "Wrote " + str(nowish) + " to time_tracker")
            else:
                sincetime = int(timelist[-2][:-1])-86400
                alltimes.write(str(nowish) + '\n')
                ew.log("DEBUG", "Wrote " + str(nowish) + " to time_tracker")
            alltimes.close()

            try:
                alltimes = open(tracker_filename, 'r+b')
            except :
                ew.log("ERROR", "Could not open file " + tracker_filename + " for reading.")
            timelist = alltimes.readlines()
            alltimes.close()
            
            try:
                alltimes = open(tracker_filename, 'w')
            except :
                ew.log("ERROR", "Could not open file " + tracker_filename + " for writing.")
            alltimes.writelines(timelist[-2:])
            alltimes.close()

            
            ioc_query = {'format': 'json', 'since':sincetime}  # add 'since':backthenish to choose window (cranky)
            iocs = parseJsonAndPrint("api.isightpartners.com", "/view/iocs", urllib.urlencode(ioc_query), pub_key, priv_key)
            #ew.log("DEBUG", "getData iocs=" + iocs)
            if issubclass(type(iocs), list):
                ew.log("DEBUG", "getData Returned a list")
                for ioc in iocs:
                    event = Event()
                    event.stanza = input_name
                    jioc = json.dumps(ioc)
                    event.data = jioc
                    # Tell the EventWriter to write this event
                    ew.write_event(event)
                    #ew.log("DEBUG", "write_event=" + event)
            #ew.log("DEBUG", "Sleeping for 60 seconds")
            #time.sleep(60)
            #ew.log("DEBUG", "I woke up.")

if __name__ == "__main__":
    sys.exit(MyScript().run(sys.argv))
