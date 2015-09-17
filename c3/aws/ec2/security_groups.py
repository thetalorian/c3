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
''' Manages AWS security groups '''
from time import sleep
from boto.exception import EC2ResponseError
from c3.utils import logging


class SecurityGroups(object):
    ''' Class to manage Security Groups '''
    def __init__(self, conn, name, find_only=False, verbose=False):
        self.conn = conn
        self.name = name
        self.sgrp = None
        self.find_only = find_only
        self.verbose = verbose
        try:
            self.sgrp = conn.get_all_security_groups(name)[0]
        except (IndexError, EC2ResponseError), msg:
            if not self.find_only:
                logging.info('Creating SG %s' % self.name)
                self.sgrp = self.create()
            else:
                logging.error(msg.message)

    def create(self):
        ''' Creates a new Security Group '''
        desc = '%s C3 SG auto group' % self.name
        try:
            return self.conn.create_security_group(self.name, desc)
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None

    def add_ingress(self, port_pair, protocol, src_cidr=None,
                    src_acct=None, src_sg=None):
        ''' Add Ingress rule '''
        # pylint: disable=too-many-arguments
        # Appropriate number arguments of for add_ingress
        if src_cidr:
            try:
                self.sgrp.authorize(protocol, port_pair[0],
                                    port_pair[1], src_cidr)
                return True
            except EC2ResponseError, msg:
                if msg.error_code == 'InvalidPermission.Duplicate':
                    logging.debug(msg.error_message, self.verbose)
                else:
                    logging.error(msg.error_message)
                    return False
        elif src_acct and src_sg:
            try:
                self.conn.authorize_security_group(
                    self.name, src_sg, src_acct,
                    protocol, port_pair[0], port_pair[1], None)
                return True
            except EC2ResponseError, msg:
                if msg.error_code == 'InvalidPermission.Duplicate':
                    logging.debug(msg.error_message, self.verbose)
                else:
                    logging.error(msg.error_message)
                    return False
        else:
            logging.error(
                'add_ingress(port_pair=%s, protocol=%s, src_cidr=%s, '
                'rc_acct=%s, src_sg=%s) FAILED (missing data?)' %
                (port_pair, protocol, src_cidr, src_acct, src_sg))
            return False

    def destroy(self):
        ''' Destroys a Security Group '''
        stime = 10
        timeout = 120
        while timeout > 0:
            try:
                self.sgrp.delete()
                return True
            except EC2ResponseError:
                logging.warn(
                    "SG %s could not be removed, sleeping %ds" %
                    (self.name, stime))
                sleep(stime)
                timeout -= stime
        logging.error('SG %s could not be deleted')
