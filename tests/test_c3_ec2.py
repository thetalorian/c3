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
''' Tests for c3.aws modules '''

import os
import sys
import moto
from c3.aws.ec2 import ebs
from zambi import ZambiConn
from c3.aws.ec2 import instances
from nose.tools import assert_equal
from nose.tools import assert_raises
from boto.exception import EC2ResponseError


class TestC3EC2(object):
    ''' testMatch class for C3 AWS libs'''
    def __init__(self):
        mock = moto.ec2.mock_ec2()
        mock.start()
        mapfile = os.getcwd() + '/tests/conf/account_aliases_map.txt'
        cmgr = ZambiConn(mapfile=mapfile)
        os.environ['AWS_CRED_DIR'] = os.getcwd() + '/tests'
        conn = cmgr.get_connection('opsqa')
        self.ebs = ebs.C3EBS(conn)
        self.ec2 = instances.C3Instance(conn)

    def test_mock_instance(self):
        ''' Test mock for ec2 instance '''
        user_data = {}
        self.ec2.start('ami-12345', 'fake.pem', 'devtst', user_data,
                       'aws1devtst1', 'm3.medium', 'us-east-1b',
                       'default_install', False, False)
        print >> sys.stdout, 'EC2 ID: %s' % self.ec2.inst_id

    def test_mock_volume(self):
        ''' Test mock for ebs volumes '''
        self.test_mock_instance()
        assert self.ebs.set_ebs_del_on_term(
            self.ec2.inst_id, '/dev/sda1') == True
        assert self.ebs.set_ebs_del_on_term(
            'i-12345', '/dev/sda1') == None
        vol = self.ebs.create_volume('10', 'us-east-1b')
        print  >> sys.stdout, 'Vol ID: %s' % vol.id
        assert self.ebs.attach_volume(
            vol.id, self.ec2.inst_id, '/dev/sdf') == True
        assert self.ebs.attach_volume(
            'vol-12345', self.ec2.inst_id, '/dev/xxx') == None
        desc = 'Testing snapshot'
        snap = self.ebs.create_snapshot(vol.id, desc)
        assert self.ebs.create_snapshot('vol-12345', desc) == None
        assert self.ebs.delete_snapshot(snap.id) == True
        assert self.ebs.delete_snapshot('snap-12345') == None
        assert self.ebs.detach_volume(
            vol.id, self.ec2.inst_id, '/dev/sdf') == True
        assert self.ebs.detach_volume(
            'vol-12345', self.ec2.inst_id, '/dev/sdf') == None
        assert self.ebs.delete_volume(vol.id) == True
        assert self.ebs.delete_volume('vol-12345') == None
