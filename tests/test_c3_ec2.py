# Copyright 2016 CityGrid Media, LLC
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
import c3.utils.config
from c3.aws.ec2 import ebs
from c3.aws.ec2 import elb
from zambi import ZambiConn
from c3.aws.ec2 import instances
from nose.tools import assert_equal
from nose.tools import assert_raises
from c3.aws.ec2 import security_groups
from boto.exception import EC2ResponseError


class TestC3Cluster(object):
    ''' testMatch class for C3Cluster '''
    def __init__(self):
        mock = moto.ec2.mock_ec2()
        mock.start()
        mapfile = os.getcwd() + '/tests/conf/account_aliases_map.txt'
        cmgr = ZambiConn(mapfile=mapfile)
        os.environ['AWS_CRED_DIR'] = os.getcwd() + '/tests'
        self.conn = cmgr.get_connection('opsqa')
        self.ec2mock = TestC3Instance()
        self.cluster = instances.C3Cluster(self.conn)

    def test_cluster_instances(self):
        ''' Test c3 cluster instances '''
        self.cluster.get_instances(instance_ids=['i-12345'])
        assert self.cluster.instances == []
        cluster = instances.C3Cluster(self.conn, 'devtst')
        assert cluster.instances == []
        self.ec2mock.test_mock_instance()
        self.cluster.get_instances(instance_ids=[self.ec2mock.ec2.inst_id])
        assert self.cluster.get_instance_ids() == [self.ec2mock.ec2.inst_id]
        self.cluster.add_instance('aws1fake1')
        assert self.cluster.c3instances[1] == 'aws1fake1'

    def test_cluster_destroy(self):
        ''' Test c3 cluster destroy '''
        self.ec2mock.test_mock_instance()
        self.cluster.get_instances(instance_ids=[self.ec2mock.ec2.inst_id])
        assert self.cluster.destroy() == 1
        assert self.cluster.destroy() == 1

    def test_cluster_hibernate(self):
        ''' Test cluster hibernate '''
        self.ec2mock.test_mock_instance()
        self.cluster.get_instances(instance_ids=[self.ec2mock.ec2.inst_id])
        assert self.cluster.hibernate() == 1

    def test_cluster_wake(self):
        ''' Test cluster wake '''
        self.ec2mock.test_mock_instance()
        self.cluster.get_instances(instance_ids=[self.ec2mock.ec2.inst_id])
        self.cluster.hibernate()
        assert self.cluster.wake() == 1


class TestC3Instance(object):
    ''' testMatch class for C3Instance'''
    def __init__(self):
        mock = moto.ec2.mock_ec2()
        mock.start()
        mapfile = os.getcwd() + '/tests/conf/account_aliases_map.txt'
        cmgr = ZambiConn(mapfile=mapfile)
        os.environ['AWS_CRED_DIR'] = os.getcwd() + '/tests'
        self.conn = cmgr.get_connection('opsqa')
        self.ec2 = instances.C3Instance(self.conn)

    def test_mock_instance(self):
        ''' Test mock for ec2 instance '''
        user_data = {}
        self.ec2.start(
            'ami-12345', 'fake.pem', 'devtst', user_data,
            'aws1devtst1', 'm3.medium', 'us-east-1b',
            'default_install', True, True)

    def test_wait_for_instance(self):
        ''' Test waiting for instance to fully start '''
        self.test_mock_instance()
        assert instances.wait_for_instance(self.ec2) == True

    def test_get_instance_objects(self):
        ''' Test c3 instance get methods '''
        self.test_mock_instance()
        assert self.ec2.get_id() == self.ec2.inst_id
        assert self.ec2.get_non_root_volumes() == {}
        assert self.ec2.get_ebs_optimized() == False
        assert self.ec2.get_az() == 'None'
        assert self.ec2.get_state() == 'running'

    def test_eip_functions(self):
        ''' Test getting an EIP by address '''
        self.test_mock_instance()
        eip = self.conn.allocate_address()
        get_eip = self.ec2.get_eip_by_addr(eip.public_ip)
        assert get_eip.public_ip == eip.public_ip
        self.ec2.re_associate_eip(eip=eip)
        assert self.ec2.reeip.public_ip == eip.public_ip
        self.conn.associate_address(self.ec2.inst_id, eip.public_ip)
        self.ec2.destroy_eip()
        eip = self.conn.allocate_address()
        assert self.ec2.set_eip(eip.public_ip) == True


class TestC3EBS(object):
    ''' test Match class for C3EBS '''
    def __init__(self):
        mock = moto.ec2.mock_ec2()
        mock.start()
        mapfile = os.getcwd() + '/tests/conf/account_aliases_map.txt'
        cmgr = ZambiConn(mapfile=mapfile)
        os.environ['AWS_CRED_DIR'] = os.getcwd() + '/tests'
        conn = cmgr.get_connection('opsqa')
        self.ebs = ebs.C3EBS(conn)
        self.ec2mock = TestC3Instance()

    def test_mock_volume(self):
        ''' Test mock for ebs volumes '''
        self.ec2mock.test_mock_instance()
        assert self.ebs.set_ebs_del_on_term(
            self.ec2mock.ec2.inst_id, '/dev/sda1') == True
        assert self.ebs.set_ebs_del_on_term(
            'i-12345', '/dev/sda1') == None
        vol = self.ebs.create_volume('10', 'us-east-1b')
        print  >> sys.stdout, 'Vol ID: %s' % vol.id
        assert self.ebs.attach_volume(
            vol.id, self.ec2mock.ec2.inst_id, '/dev/sdf') == True
        assert self.ebs.attach_volume(
            'vol-12345', self.ec2mock.ec2.inst_id, '/dev/xxx') == None
        desc = 'Testing snapshot'
        snap = self.ebs.create_snapshot(vol.id, desc)
        assert self.ebs.create_snapshot('vol-12345', desc) == None
        assert self.ebs.delete_snapshot(snap.id) == True
        assert self.ebs.delete_snapshot('snap-12345') == None
        assert self.ebs.detach_volume(
            vol.id, self.ec2mock.ec2.inst_id, '/dev/sdf') == True
        assert self.ebs.detach_volume(
            'vol-12345', self.ec2mock.ec2.inst_id, '/dev/sdf') == None
        assert self.ebs.delete_volume(vol.id) == True
        assert self.ebs.delete_volume('vol-12345') == None


class TestC3ELB(object):
    ''' testMatch class for C3ELB '''
    def __init__(self):
        self.cconfig = self.get_test_config()
        mock = moto.elb.mock_elb()
        mock.start()
        mapfile = os.getcwd() + '/tests/conf/account_aliases_map.txt'
        cmgr = ZambiConn(mapfile=mapfile)
        os.environ['AWS_CRED_DIR'] = os.getcwd() + '/tests'
        self.conn = cmgr.get_connection('opsqa', service='elb')
        self.elb = None

    def get_test_config(self):
        ''' Get the test config '''
        mapfile = os.getcwd() + '/tests/confs/account_aliases_map.txt'
        os.environ['AWS_CONF_DIR'] = os.getcwd() + '/tests/confs'
        os.environ['AWS_BASE_DIR'] = os.getcwd() + '/tests'
        os.environ['HOME'] = os.getcwd() + '/tests/confs'
        config = os.getcwd() + '/tests/confs/devpro.ini'
        return c3.utils.config.ClusterConfig(
            ini_file=config, account_name='opsqa')

    def test_create_elb(self):
        ''' Test create ELB '''
        self.elb = elb.C3ELB(
            self.conn, 'aws1dviptst1', self.cconfig.get_elb_config())
        assert self.elb.created == True

class TestC3SecurityGroups(object):
    ''' testMatch class for C3SecurityGroups '''
    def __init__(self):
        mock = moto.ec2.mock_ec2()
        mock.start()
        mapfile = os.getcwd() + '/tests/conf/account_aliases_map.txt'
        cmgr = ZambiConn(mapfile=mapfile)
        os.environ['AWS_CRED_DIR'] = os.getcwd() + '/tests'
        self.conn = cmgr.get_connection('opsqa')
        self.sgrp = None

    def test_create_sg(self):
        ''' Test Create Security Group '''
        self.sgrp = security_groups.SecurityGroups(self.conn, 'devtst')
        assert self.sgrp.sgrp.name == 'devtst'

    def test_add_ingress(self):
        ''' Test add SG ingress rule '''
        self.sgrp = security_groups.SecurityGroups(self.conn, 'devtst')
        assert self.sgrp.add_ingress(
            ['80','80'], 'tcp', src_cidr='111.111.111.111/32') == True
        assert self.sgrp.add_ingress(
            ['80', '80'], 'tcp', src_acct='opsqa', src_sg='default') == True

    def test_destroy_sg(self):
        ''' Test destroy SG '''
        self.sgrp = security_groups.SecurityGroups(self.conn, 'devtst')
        assert self.sgrp.destroy() == True
