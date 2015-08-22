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


class C3ClusterNotFoundException(Exception):
    ''' Cluster not found exception '''
    def __init__(self, value):
        super(C3ClusterNotFoundException, self).__init__(value)
        self.name = value

    def __str__(self):
        return repr("C3Cluster %s not found" % self.name)


class TooManySGsException(Exception):
    ''' Too many SGs exception '''
    def __init__(self, value, sgs):
        super(TooManySGsException, self).__init__(value)
        super(TooManySGsException, self).__init__(sgs)
        self.name = value
        self.sgs = sgs

    def __str__(self):
        return repr("C3Cluster %s not found %s" % (self.name, self.sgs))


class C3Cluster(object):
    ''' The cluster specifc to ct_env and ct_class. '''
    def __init__(self, conn, name, nventory=None, verbose=None):
        self.conn = conn
        self.name = name
        self.nventory = nventory
        self.verbose = verbose
        self.instances = list()
        self.c3instances = list()
        self.get_instances()

    def get_instances(self):
        ''' Get both instances and C3instances '''
        try:
            sgrps = self.conn.get_all_security_groups([self.name])
            if len(sgrps) > 1:
                raise TooManySGsException(self.name, sgrps)
            if len(sgrps) < 1:
                raise C3ClusterNotFoundException(self.name)
            sgrp = sgrps[0]
        except:
            raise C3ClusterNotFoundException(self.name)
        try:
            self.instances = sgrp.instances()
        except EC2ResponseError, msg:
            logging.error(msg.message)
        # we should really use C3Instances for everything
        for inst in self.instances:
            self.c3instances.append(C3Instance(
                self.conn, inst_id=inst.id,
                nventory=self.nventory, verbose=self.verbose))
        return self.instances

    def get_instance_ids(self):
        ''' Returns instance IDs '''
        ids = list()
        for iid in self.instances:
            ids.append(iid.id)
        return ids

    def add_instance(self, c3instance):
        ''' Add instance to cluster. '''
        self.c3instances.append(cginstance)

    def destroy(self):
        ''' Terminates instances in cluster. '''
        for iid in self.c3instances:
            if iid.get_state() not in ['terminated']:
                logging.debug(
                    '%s.terminate() (%s: %s)' %
                    (iid.id, iid.name, iid.get_state()), self.verbose)
                iid.destroy()

    def hibernate(self):
        ''' Hibernate instances in cluster. '''
        count = 0
        for iid in self.c3instances:
            if iid.hibernate():
                count += 1
        return count

    def wake(self):
        ''' Wake instances in cluster. '''
        count = 0
        for iid in self.c3instances:
            if iid.wake():
                count += 1
        wcount = self.wait_cluster()
        if wcount != count:
            logging.warn(
                'Asked for %d but only %d started' %(count, wcount))
        return wcount

    def wait_cluster(self, desired_state="up", timeout=120):
        ''' Waits for cluster to start. '''
        stt = time.time()
        while time.time() - stt < timeout:
            time.sleep(10)
            done = self.analyze_cluster(desired_state)
            if done > 0:
                return done
        logging.error(
            'wait_cluster() timed out after %ds' % (timeout))
        return 0

    def analyze_cluster(self, desired_state="up"):
        ''' Analyze cluster state. '''
        done = 0
        for iid in self.c3instances:
            state = iid.analyze_state(desired_state)
            if state == 1:
                return -1
            elif state == 0:
                done += 1
        return done


class C3Instance(object):
    ''' Class that manages instance objects '''
    # pylint:disable=too-many-instance-attributes
    # Required for boto API
    def __init__(self, conn, inst_id=None, nventory=None, verbose=False):
        self.conn = conn
        self.inst_id = inst_id
        self.verbose = verbose
        self._instance = None
        self._reservation = None
        self.start_time = None
        self.registered = False
        self.nventory = nventory
        self.allocateeips = None
        self.state = None
        self.name = None
        self.reeip = None
        if inst_id:
            self._instance = conn.get_all_instances([inst_id])[0].instances[0]
            self.name = self._instance.tags.get("Name") or self.inst_id
            self.state = self._instance.state

    def start(self, ami, sshkey, sgs, user_data, hostname,
              isize, zone, nodegroups, allocateeips, use_ebsoptimized):
        ''' Starts an EC2 instance '''
        # pylint:disable=too-many-arguments
        # Required for boto API
        try:
            logging.debug(
                'C3Instance.start(%s, %s, %s, %s, %s, %s, %s, %s, %s)' %
                (ami, sshkey, sgs, len(user_data), hostname, isize, zone,
                 "[tags]", nodegroups), self.verbose)
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
        while True and safety:
            try:
                self._instance.add_tag('Name', hostname)
                break
            except EC2ResponseError, msg:
                logging.error(msg.message)
            safety -= 1
            time.sleep(1)
        self.nv_register(self._instance.id, hostname)
        if nodegroups:
            self.nv_add_node_groups(self._instance.id, nodegroups)
        self.start_time = time.time()
        return self._instance.id

    def nv_register(self, inst_id, hostname):
        ''' Try to register the new instance with nventory '''
        if self.nventory:
            return self.nventory.register_host(hostname, inst_id)

    def nv_add_node_groups(self, inst_id, nodegroups):
        ''' Try to register the new instance with nventory '''
        if self.nventory:
            return self.nventory.add_node_groups(inst_id, nodegroups)

    def nv_set_state(self, status):
        ''' Set nVentory state for instance '''
        if self.nventory:
            return self.nventory.setStatus(self.inst_id, status)

    def get_id(self):
        ''' Return the EC2 Instance ID '''
        return self._instance.id

    def get_non_root_volumes(self):
        ''' Returns a list of non root ebs volumes attached to the instance. '''
        vols = dict()
        inst = self._instance
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
            'In %s.finalize_start()' % self.inst_id, self.verbose)
        if self.allocateeips:
            return self.new_eip()
        if self.reeip:
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

    def get_nv_eip(self, steal=False):
        ''' Figure out if my nv hostname is an EIP '''
        mynv = self.nventory.get_node_by_instance_id(self.inst_id)[0]
        try:
            myip = socket.gethostbyname(mynv['name'])
        except socket.gaierror, msg:
            logging.error(msg)
            return None
        eip = self.get_eip_by_addr(myip)
        if eip:
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

    def re_associate_eip(self, steal=False):
        ''' Reassociates an EIP address to an EC2 instance '''
        eip = self.get_nv_eip(steal)
        if eip:
            logging.debug(
                'Will re-associate EIP %s to %s' %
                (eip.public_ip, self.inst_id), self.verbose)
            self.reeip = eip

    def destroy_eip(self):
        ''' Destroy EIP address associated with an EC2 instance '''
        eip = self.get_associated_eip()
        if eip:
            try:
                eip.disassociate()
            except EC2ResponseError, msg:
                logging.error(msg.message)
                return None
            tries = 1
            while tries <= 10:
                logging.debug(
                    'EIP released on try %d' % tries,
                    self.verbose)
                try:
                    eip.release()
                    return True
                except EC2ResponseError, msg:
                    logging.error(msg.message)
                    return None
                tries += 1
                time.sleep(5)
            return False
        return True

    def destroy(self):
        ''' Teardown and terminate an EC2 Instance '''
        logging.debug(
            'Checking to see if we need to destory EIP', self.verbose)
        if self.destroy_eip():
            try:
                return self._instance.terminate()
            except EC2ResponseError, msg:
                logging.error(msg.message)
                return None
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
                '%s.stop() (%s: %s)' %
                (self.inst_id, name_tag, self.get_state()), self.verbose)
            return self.nv_set_state('hibernating')
        return False

    def wake(self):
        ''' Start an EC2 instance that is stopped '''
        if self.get_state() == 'stopped':
            name_tag = self._instance.tags.get('Name')
            self.re_associate_eip()
            try:
                self._instance.start()
            except EC2ResponseError, msg:
                logging.error(msg.message)
                return None
            logging.debug(
                '%s.start() (%s: %s)' %
                (self.inst_id, name_tag, self.get_state()), self.verbose)
            return self.nv_set_state('inservice')
        return False
