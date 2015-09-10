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
""" This module is used for interfacig with AWS EBS """
from time import sleep
from c3.utils import logging
from boto.exception import EC2ResponseError


class C3EBS(object):
    """ This class is used to manage EBS """
    def __init__(self, conn):
        self.conn = conn

    def create_volume(self, ebs_size, zone, ebs_type='standard', iops=None):
        """
        Create a volume within a given zone. Support for EBS IOPS is included
        """
        vol = list()
        try:
            vol = self.conn.create_volume(
                ebs_size,
                zone,
                snapshot=None,
                volume_type=ebs_type,
                iops=iops)
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None
        return vol

    def delete_volume(self, volid):
        """ Delete unnattached EBS volume """
        try:
            self.conn.delete_volume(volid)
            return True
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None

    def attach_volume(self, vol_id, instance_id, ebs_device):
        """ Attach a volume to an instance that was created """
        try:
            self.conn.attach_volume(vol_id, instance_id, ebs_device)
            return True
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None

    def detach_volume(self, vol_id, instance_id, ebs_device):
        """ Detach a volume to from an instance """
        try:
            self.conn.detach_volume(vol_id, instance_id, ebs_device)
            return True
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None

    def set_ebs_del_on_term(self, instance_id, device):
        """ Set volumes to delete upon termination """
        mvolume = [device + '=true']
        logging.info(
            "Setting delete attribute for %s on %s" %
            (mvolume, instance_id))
        try:
            self.conn.modify_instance_attribute(
                instance_id, 'blockDeviceMapping', mvolume)
            return True
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None

    def create_snapshot(self, vol_id, desc):
        """ Creates an EBS Snapshot """
        logging.info('Creating Snapshot from %s' % vol_id)
        try:
            snap = self.conn.create_snapshot(vol_id, description=desc)
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None
        logging.info('Snapshot created %s: %s' % (snap.id, desc))
        return snap

    def delete_snapshot(self, snap_id):
        ''' Delete a snapshot '''
        logging.info('Deleting snapshot: %s' % snap_id)
        try:
            return self.conn.delete_snapshot(snap_id)
        except EC2ResponseError, msg:
            logging.error(msg.message)
            return None
