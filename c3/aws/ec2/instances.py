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
''' This module manages EC2 clusters and instance objects '''
import time
import socket
from c3.utils import logging
from boto.exception import EC2ResponseError


def wait_for_instance(instance, desired_state="up", timeout=120, verbose=False):
    ''' Waits for instance to enter desired state. '''
    logging.debug('Instance: %s, Desired State: %s' %
                  (instance.name, desired_state), verbose)
    stt = time.time()
    while time.time() - stt < timeout:
        time.sleep(10)
        state = instance.analyze_state(desired_state)
        if state == 0:
            logging.debug('Instance entered desired state: %s' %
                          desired_state, verbose)
            return True
        elif state == 2:
            logging.error('Instance failed to enter desired state: %s' %
                          desired_state)
            return False
    logging.error(
        'Waiting for %s timed out after %ds' % (instance.name, timeout))
    return False


class C3Cluster(object):
    ''' The cluster specifc to ct_env and ct_class. '''
    def __init__(self, conn, name=None, node_db=None, verbose=None):
        self.conn = conn
        self.name = name
        self.node_db = node_db
        self.verbose = verbose
        self.instances = list()
        self.c3instances = list()
        if self.name is not None:
            self.get_instances()

    def get_instances(self, instance_ids=None):
        ''' Get both instances and C3instances '''
        if instance_ids:
            all_instances = None
            instances = list()
            try:
                all_instances = self.conn.get_all_instances(
                    instance_ids=instance_ids)
            except EC2ResponseError, msg:
                logging.error(msg.message)
                return None
            for instance in all_instances:
                instances.append(instance.instances[0])
            self.instances = instances
        else:
            try:
                sgrp = self.conn.get_all_security_groups(self.name)[0]
            except IndexError:
                logging.error('No instances found: check name %s' % self.name)
                return None
            try:
                self.instances = sgrp.instances()
            except EC2ResponseError, msg:
                logging.error(msg.message)
        # we should really use C3Instances for everything
        for inst in self.instances:
            self.c3instances.append(C3Instance(
                self.conn, inst_id=inst.id,
                node_db=self.node_db, verbose=self.verbose))
        return self.instances

    def get_instance_ids(self):
        ''' Returns instance IDs '''
        ids = list()
        for iid in self.instances:
            ids.append(iid.id)
        return ids

    def add_instance(self, c3instance):
        ''' Add instance to cluster. '''
        self.c3instances.append(c3instance)

    def destroy(self):
        ''' Terminates instances in cluster. '''
        count = 0
        for iid in self.c3instances:
            if iid.get_state() not in ['terminated']:
                if iid.destroy():
                    logging.info(
                        'Waiting for %s (%s) to terminate' %
                        (iid.name, iid.inst_id))
                    if wait_for_instance(iid, desired_state='down',
                                         verbose=self.verbose):
                        count += 1
            else:
                logging.warn('%s already teriminated' % iid.name)
                count += 1
        if count != len(self.c3instances):
            logging.warn(
                'Asked for %d but only %d terminated' %
                (len(self.c3instances), count))
        return count

    def hibernate(self):
        ''' Hibernate instances in cluster. '''
        count = 0
        for iid in self.c3instances:
            if iid.hibernate():
                logging.info('Waiting for %s to stop' % iid.name)
                if wait_for_instance(iid, desired_state='down',
                                     verbose=self.verbose):
                    count += 1
        if count != len(self.c3instances):
            logging.warn(
                'Asked for %d but only %d stopped' %
                (len(self.c3instances), count))
        return count

    def wake(self):
        ''' Wake instances in cluster. '''
        count = 0
        for iid in self.c3instances:
            if iid.wake():
                logging.info('Waiting for %s to start' % iid.name)
                if wait_for_instance(iid, verbose=self.verbose):
                    logging.debug('Wait for %s successful' %
                                  iid.name, self.verbose)
                    count += 1
        if count != len(self.c3instances):
            logging.warn(
                'Asked for %d but only %d started' %
                (len(self.c3instances), count))
        return count


class C3Instance(object):
    ''' Class that  manages instance objects '''
    # pylint:disable=too-many-instance-attributes
    # Required for boto API
    def __init__(self, conn, inst_id=None, node_db=None, verbose=False):
        self.conn = conn
        self.inst_id = inst_id
        self.verbose = verbose
        self._instance = None
        self._reservation = None
        self.start_time = None
        self.registered = False
        self.node_db = node_db
        self.allocateeips = None
        self.state = None
        self.name = None
        self.reeip = None
        self.eip = None
        if inst_id:
            self._instance = conn.get_all_instances([inst_id])[0].instances[0]
            self.name = self._instance.tags.get("Name") or self.inst_id
            self.state = self._instance.state

    def start(self, ami, sshkey, sgs, user_data, hostname,
              isize, zone, nodegroups, allocateeips, use_ebsoptimized):
        ''' Starts an EC2 instance '''
        # pylint:disable=too-many-arguments
        # Required for boto API
        logging.debug(
            'C3Instance.start(%s, %s, %s, %s, %s, %s, %s, %s)' %
            (ami, sshkey, sgs, len(user_data), hostname, isize, zone,
             nodegroups), self.verbose)
        try:
            self._reservation = self.conn.run_instances(
                ami, 1, 1, sshkey, sgs, user_data, None, isize, zone,
                None, None, False, None, None, ebs_optimized=use_ebsoptimized)
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None
        self._instance = self._reservation.instances[0]
        self.inst_id = self._instance.id
        self.name = hostname
        self.allocateeips = allocateeips
        safety = 10
        while safety:
            try:
                self._instance.add_tag('Name', hostname)
                break
            except EC2ResponseError, msg:
                logging.error(msg.message)
            safety -= 1
            time.sleep(1)
        if self.node_db:
            self.node_register(self._instance.id, hostname)
            if nodegroups:
                self.add_node_groups(self._instance.id, nodegroups)
        self.start_time = time.time()
        return self._instance.id

    def node_register(self, inst_id, hostname):
        ''' Try to register the new instance with node_db '''
        return self.node_db.register_host(hostname, inst_id)

    def add_node_groups(self, inst_id, nodegroups):
        ''' Try to register the new instance with node_db '''
        return self.node_db.add_node_groups(inst_id, nodegroups)

    def set_state(self, status):
        ''' Set nVentory state for instance '''
        return self.node_db.set_status(self.inst_id, status)

    def get_id(self):
        ''' Return the EC2 Instance ID '''
        return self._instance.id

    def get_non_root_volumes(self):
        ''' Returns a list of non root ebs volumes attached to the instance. '''
        vols = dict()
        inst = self._instance
        if inst.block_device_mapping:
            for block in inst.block_device_mapping:
                if '/dev/sda1' not in block:
                    vols[block] = inst.block_device_mapping[block].volume_id
        return vols

    def get_ebs_optimized(self):
        ''' Return ebs optimized option '''
        return self._instance.ebs_optimized

    def get_az(self):
        ''' Return the AZ '''
        return self._instance.placement

    def get_state(self):
        ''' Update the state and return '''
        self.state = self._instance.update()
        return self.state

    def analyze_state(self, desired_state='up'):
        ''' Find out if we're done (0), waiting (1), or screwed (2) '''
        result = None
        state = self.get_state()
        if state:
            logging.debug(
                'Analyze state %s is %s' % (self._instance.id, state),
                self.verbose)
            pending_up = ['pending']
            pending_down = ['shutting-down', 'stopping']
            ec2_up = 'running'
            ec2_down = ['terminated', 'stopped']
            if desired_state is 'up':
                if state in pending_up:
                    result = 1
                elif state in pending_down:
                    result = 2
                elif state == ec2_up:
                    self.finalize_start()
                    result = 0
            else:
                if state in pending_down:
                    result = 1
                elif state == ec2_up:
                    result = 2
                elif state in ec2_down:
                    result = 0
            return result
        else:
            logging.error('Unable to get status for %s' % self._instance.id)
            return False

    def finalize_start(self):
        ''' Perform EC2 actions once the instance is finally 'running' '''
        logging.debug(
            'Finalize start: %s' % self.inst_id, self.verbose)
        if self.allocateeips:
            return self.new_eip()
        if self.reeip:
            logging.debug('Reassociating EIP %s with instance %s' %
                          (self.reeip, self.inst_id), self.verbose)
            try:
                self.reeip.associate(self.inst_id)
                self.reeip = None
                return True
            except EC2ResponseError, msg:
                logging.error(msg.message)
                return None
        return True

    def get_eip_by_addr(self, myip):
        ''' Return an EIP address '''
        try:
            eips = self.conn.get_all_addresses()
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None
        for eip in eips:
            if myip == eip.public_ip:
                return eip
        return None

    def set_eip(self, address):
        ''' Set the EIP for the instance '''
        try:
            self.eip = self.get_eip_by_addr(address)
            return True
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None

    def get_eip(self, steal=False):
        ''' Figure out if my hostname is an EIP '''
        if self.eip:
            return self.eip
        data = self.node_db.get_node_by_instance_id(self.inst_id)[0]
        try:
            myip = socket.gethostbyname(data['ec2_public_hostname'])
        except socket.gaierror, msg:
            logging.error(msg)
            return None
        logging.debug('myip: %s' % myip, self.verbose)
        eip = self.get_eip_by_addr(myip)
        if eip:
            logging.debug('EIP: %s associated with %s' % (eip, eip.instance_id),
                          self.verbose)
            if steal or not eip.instance_id:
                return eip
        return None

    def get_associated_eip(self):
        ''' Return EIP associated with EC2 instance '''
        try:
            eips = self.conn.get_all_addresses()
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None
        if eips:
            for eip in eips:
                if eip.instance_id == self.inst_id:
                    return eip
        return None

    def new_eip(self):
        ''' Allocates a new EIP address to an EC2 instance '''
        logging.debug('Allocating a new EIP!', self.verbose)
        self.allocateeips = False
        try:
            eip = self.conn.allocate_address()
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None
        try:
            return eip.associate(self.inst_id)
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None

    def re_associate_eip(self, steal=False, eip=None):
        ''' Reassociates an EIP address to an EC2 instance '''
        if self.node_db:
            logging.debug('Checking for EIP', self.verbose)
            eip = self.get_eip(steal)
        else:
            logging.info('No external data source is defined, skipping')
        if eip:
            logging.debug(
                'Will re-associate EIP %s to %s' %
                (eip.public_ip, self.inst_id), self.verbose)
            self.reeip = eip
        else:
            self.reeip = None

    def destroy_eip(self):
        ''' Destroy EIP address associated with an EC2 instance '''
        eip = self.get_associated_eip()
        if eip:
            logging.info('Disassociating EIP from %s' % self.name)
            try:
                eip.disassociate()
            except EC2ResponseError, msg:
                logging.error(msg.message)
                return None
            tries = 1
            while tries <= 10:
                try:
                    eip.release()
                    logging.debug(
                        'EIP released on try %d' % tries,
                        self.verbose)
                    return True
                except EC2ResponseError, msg:
                    logging.error(msg.message)
                    return None
                tries += 1
                time.sleep(5)
            return False
        else:
            logging.debug('No EIP to delete', self.verbose)
            return True

    def destroy(self):
        ''' Teardown and terminate an EC2 Instance '''
        logging.debug(
            'Checking to see if we need to destory EIP', self.verbose)
        if self.destroy_eip():
            logging.debug('Terminating %s' % self.name, self.verbose)
            try:
                self._instance.terminate()
            except EC2ResponseError, msg:
                logging.error(msg.message)
                return None
            return True
        else:
            logging.error('Unable to destroy EIP, cancel terminating instance')
            return False

    def hibernate(self):
        ''' Hibernate an EC2 instance '''
        if self.get_state() == 'running':
            name_tag = self._instance.tags.get('Name')
            try:
                self._instance.stop()
            except EC2ResponseError, msg:
                logging.error(msg.message)
                return None
            logging.debug(
                'stopped (%s: %s) state: %s' %
                (self.inst_id, name_tag, self.get_state()), self.verbose)
            if self.node_db:
                return self.set_state('hibernating')
            else:
                return True

    def wake(self):
        ''' Start an EC2 instance that is stopped '''
        if self.get_state() == 'stopped':
            name_tag = self._instance.tags.get('Name')
            logging.debug('Attempt starting instance %s' %
                          name_tag, self.verbose)
            self.re_associate_eip()
            try:
                self._instance.start()
            except EC2ResponseError, msg:
                logging.error(msg.message)
                return None
            logging.debug(
                'Start succeeded (%s: %s) state: %s' %
                (self.inst_id, name_tag, self.get_state()), self.verbose)
            if self.node_db:
                return self.set_state('inservice')
            else:
                return True
