# Copyright 2015 CityGrid Media, LLC
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
''' This module sends metrics directly to graphite. '''

import re
import socket
import time
from c3.utils import logging


class Graphite(object):
    ''' This class sends metrics to graphite. '''
    def __init__(self, server=None, port=2003, debug=False):
        self.server = server
        self.port = port
        self._sock = None
        self._sock_status = None
        self.prefix = None
        self.debug = debug

    def send_metric(self, name, value):
        ''' Send custom path metric to graphite. '''
        message = "%s %s %s"  % (name, value, int(time.time()))
        if self.debug:
            logging.info(message)
            return True
        if not self._sock:
            self.connect()
        if self._sock_status:
            logging.info("Sending %s %s to %s" % (name, value, self.server))
            try:
                self._sock.sendall(message + "\n")
            except socket.gaierror, msg:
                logging.error(msg)
                self._sock = None
                return False

    def send_server_metric(self, name, value, hostname=None):
        ''' Send server path metric to graphite. '''
        message = '%s.%s%s' % (self.get_server_prefix(hostname), name, value)
        if self.debug:
            logging.info(message)
            return True
        return self.send_metric(message)

    def connect(self):
        ''' Create socket connection to graphite. '''
        try:
            self._sock = socket.create_connection(
                (self.server, self.port), timeout=10)
            self._sock_status = True
        except (socket.gaierror, socket.timeout, socket.error), msg:
            self._sock_status = False
            logging.error(msg)

    def get_server_prefix(self, hostname=None):
        ''' Get FQDN for server metric path. '''
        if hostname is None:
            if self.prefix:
                return self.prefix
            hostname = socket.getfqdn()
        fqdn = re.sub(r'\.', '_', hostname)
        ct_class = fqdn[7:10]
        self.prefix = "servers.%s.%s" % (ct_class, fqdn)
        return self.prefix
