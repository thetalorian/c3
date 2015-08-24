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
''' This module managed ELB objects '''
from c3.utils import logging
from boto.ec2.elb import HealthCheck
from boto.exception import BotoServerError


class C3ELB(object):
    ''' This class is used to manage ELBs '''
    # pylint:disable=too-many-arguments
    # Appropriate number of arguments for an ELB
    def __init__(self, conn, name, conf, verbose=False, find_only=False):
        self.elb = None
        self.conn = conn
        self.name = name
        self.conf = conf
        self.azs_used = conf.get_azs()
        self.hc = None
        self.verbose = verbose
        self.find_only = find_only
        self.elb_listeners = [
            (conf.public_port, conf.private_port, conf.protocol)]
        try:
            self.elb = self.conn.get_all_load_balancers(
                load_balancer_names=[self.name])[0]
            logging.debug('Found existing ELB: %s' % self.name, self.verbose)
        except BotoServerError, msg:
            if self.find_only is False:
                self.create_elb()
            else:
                logging.error(msg.message)
                return None
        if self.elb:
            self.ensure_hc()
            self.ensure_azs()

    def add_instances(self, instances):
        ''' Add instances to ELB '''
        logging.debug('Adding instances to ELB: %s' % instances, self.verbose)
        try:
            self.elb.register_instances(instances)
        except BotoServerError, msg:
            logging.error(msg.message)

    def remove_instances(self, instances):
        ''' Remove instances from ELB '''
        logging.debug(
            "Removing instances from ELB: %s" % instances, self.verbose)
        try:
            self.elb.deregister_instances(instances)
        except BotoServerError, msg:
            logging.error(msg.message)

    def ensure_azs(self):
        ''' Ensure AZs add to ELB from config '''
        azs = self.azs_used
        logging.debug("Trying to add AZs to ELB: %s" % azs, self.verbose)
        for zone in azs:
            if zone not in self.elb.availability_zones:
                logging.debug("Adding %s to ELB" % azs, self.verbose)
                try:
                    self.elb.enable_zones(zone)
                except BotoServerError, msg:
                    logging.error(msg.message)
        logging.info('Zones configured for ELB: %s' % self.azs_used)

    def ensure_hc(self):
        ''' Ensure HC is set for ELB '''
        if self.elb.health_check is None:
            self.get_hc()
            try:
                self.elb.configure_health_check(self.hc)
            except BotoServerError, msg:
                logging.error(msg.message)
        else:
            self.get_hc()
        logging.info('ELB HC: %s' % self.hc)

    def get_hc(self):
        ''' Return the healtcheck object '''
        if self.hc:
            return self.hc
        else:
            try:
                self.hc = HealthCheck(
                    self.conf.hc_access_point,
                    self.conf.hc_interval,
                    self.conf.hc_target,
                    self.conf.hc_healthy_threshold,
                    self.conf.hc_unhealthy_threshold)
            except BotoServerError, msg:
                logging.error(msg.message)
                return None
            return self.hc

    def get_dns(self):
        ''' Return dns_name for ELB '''
        return self.elb.dns_name

    def check_elb_exists(self):
        ''' Check to see if ELB exists '''
        try:
            return self.conn.get_all_load_balancers(
                load_balancer_names=[self.name])
        except BotoServerError, msg:
            logging.error(msg.message)
            return None

    def get_instances(self):
        ''' Return instances assigned to ELB '''
        return self.elb.instances

    def get_azs(self):
        ''' Return AZs configured for ELB '''
        return self.elb.availability_zones

    def create_elb(self):
        ''' Create an ELB '''
        logging.debug('Create ELB %s' % self.name, self.verbose)
        try:
            self.elb = self.conn.create_load_balancer(
                self.name, self.azs_used, self.elb_listeners)
        except BotoServerError, msg:
            logging.error(msg.message)
            return None
        logging.info('Created %s: %s' % (self.name, self.elb))

    def instance_configured(self, inst_id):
        ''' Check if instance is configured on ELB '''
        for instance in self.get_instances():
            if instance.id == inst_id:
                return True
        return False

    def destroy(self):
        ''' Destroy an ELB '''
        try:
            return self.elb.delete()
        except BotoServerError, msg:
            logging.error(msg.message)
            return None
