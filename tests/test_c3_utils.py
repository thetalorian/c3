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
''' Tests for c3.utils '''

import os
import sys
import random
import c3.utils.config
import c3.utils.graphite
import c3.utils.naming as c3naming
import c3.utils.accounts as c3accounts
import c3.utils.jgp.gen_entry as c3gen_entry
import c3.utils.jgp.statement as c3statement
from nose.tools import assert_equal
from nose.tools import assert_raises


def test_get_account_name():
    ''' Test function in c3accounts'''
    os.environ['AWS_ACCOUNT_ID'] = '123456789011'
    mapfile = os.getcwd() + '/tests/confs/account_aliases_map.txt'
    account = c3accounts.get_account_name(mapfile=mapfile)
    assert account == None
    os.environ['AWS_ACCOUNT_ID'] = ''
    assert c3accounts.get_account_name() == False
    os.environ['AWS_ACCOUNT_ID'] = '123456789012'
    account = c3accounts.get_account_name(mapfile=mapfile)
    assert account == 'opsqa'


def test_get_account_id():
    ''' Test function in c3accounts'''
    mapfile = os.getcwd() + '/tests/confs/account_aliases_map.txt'
    account = c3accounts.get_account_id(
        account_name='opsprod', mapfile=mapfile)
    assert account == '210987654321'
    os.environ['AWS_ACCOUNT_ID'] == '123456789012'
    account = c3accounts.get_account_id()
    assert account == '123456789012'
    account = c3accounts.get_account_id(
        account_name='opsqa', mapfile=mapfile)
    assert account == '123456789012'


def test_translate_account():
    ''' Test function in c3accounts'''
    mapfile = os.getcwd() + '/tests/confs/account_aliases_map_FAKE.txt'
    assert c3accounts.translate_account(mapfile=mapfile) == False
    os.environ['AWS_CONF_DIR'] = os.getcwd() + '/tests/confs'
    name = c3accounts.translate_account(account_id='123456789012')
    assert name == 'opsqa'


def test_find_available_hostnames():
    ''' Test function in c3.utils.naming '''
    hosts = c3naming.find_available_hostnames(
        'devweb', count=2)
    assert hosts == False
    hosts = c3naming.find_available_hostnames(
        'devweb', count=2, account='opsqa',
        region='us-east-1',domain='ctgrd.com')
    assert hosts == ['aws1devweb1.opsqa.ctgrd.com',
                    'aws1devweb2.opsqa.ctgrd.com']


def test_gen_hostname():
    ''' Test function in c3.utils.naming '''
    host = c3naming.gen_hostname('devweb', 1, 'dev')
    assert host == 'aws1devweb1.dev.ctgrd.com'
    host = c3naming.gen_hostname('zzzweb', 1, 'dev')
    assert host == False


def test_get_aws_dc():
    ''' Test function in c3.utils.naming '''
    assert c3naming.get_aws_dc('us-east-1') == 'aws1'
    assert c3naming.get_aws_dc('us-west-1') == 'aws2'
    assert c3naming.get_aws_dc('eu-west-1') == 'aws3'
    assert c3naming.get_aws_dc('us-east') == False


def test_get_logging_bucket_name():
    ''' Test fuction in c3.utils.naming '''
    os.environ['AWS_CONF_DIR'] = os.getcwd() + '/tests/confs'
    bucket = c3naming.get_logging_bucket_name(account_id='123456789012')
    assert bucket == 'cgs3log-opsqa'
    bucket = c3naming.get_logging_bucket_name(account_id='123456789011')
    assert bucket == False


def test_get_cidr():
    ''' Test get_cidr function in c3.utils.naming '''
    os.environ['AWS_CONF_DIR'] = os.getcwd() + '/tests/confs'
    cidr = c3naming.get_cidr('**PUBLIC**')
    assert cidr == '0.0.0.0/0'


def test_jgp_read_config():
    ''' Test read_config in c3.utils.jgp '''
    config = 'fake.ini'
    assert c3gen_entry.read_config(config) == False
    config = os.getcwd() + '/tests/confs/opsqa-devzzz.ini'
    ini = c3gen_entry.read_config(config)
    assert ini.sections() == ['s3:get*,s3:list*', 's3:*',
                              's3:putObject', 's3:badtest']


def test_jgp_gen_s3_entry():
    ''' Test gen_s3_entry in c3.utils.jgp '''
    config = os.getcwd() + '/tests/confs/opsqa-devzzz.ini'
    ini = c3gen_entry.read_config(config)
    entry = c3gen_entry.gen_s3_entry(ini, 'devzzz', 'opsqa')
    assert entry == [
        'Allow|s3:get*,s3:list*|devzzz|opsqa|mybucket/*|'\
        'IpAddress,aws:SourceIp,216.1.187.128/27',
        'Allow|s3:putObject|devzzz|opsqa|mybucket/foo/bar/baz|empty',
        'Deny|s3:*|devzzz|opsqa|mybucket/foobar/barbaz|empty']

def test_jgp_make_statement():
    ''' Test make_statement in c3.utils.jgp.statement '''
    statement = c3statement.make_statement(
        '086441151436', 'root', 'cgm-cloudtrail/*',
        's3:GetBucketAcl','Allow', 'empty')
    assert statement == {
        'Action': ['s3:GetBucketAcl'],
        'Resource': ['arn:aws:s3:::cgm-cloudtrail/*'],
        'Effect': 'Allow',
        'Principal': {'AWS': ['arn:aws:iam::086441151436:root']}}
    statement = c3statement.make_statement(
        '086441151436','root',
        'cgm-cloudtrail/AWSLogs/150620942615/*',
        's3:PutObject','Allow',
        'StringEquals,s3:x-amz-acl,bucket-owner-full-control')
    assert statement == {
        'Action': ['s3:PutObject'],
        'Resource': ['arn:aws:s3:::cgm-cloudtrail/AWSLogs/150620942615/*'],
        'Effect': 'Allow',
        'Condition': {
            'StringEquals': {'s3:x-amz-acl': 'bucket-owner-full-control'}},
        'Principal': {'AWS': ['arn:aws:iam::086441151436:root']}}


def test_jgp_do_principal():
    ''' Test do_principal in c3.utils.jgp.statement '''
    statement = c3statement.do_principal('cidr-networks','')
    assert statement == {'AWS': '*'}
    statement = c3statement.do_principal('blah','root')
    assert statement == {'AWS': ['arn:aws:iam::blah:root']}
    statement = c3statement.do_principal('blah','user')
    assert statement == {'AWS': ['arn:aws:iam::blah:user/user']}


def test_jgp_do_condition():
    ''' Test do_condition in c3.utils.jgp '''
    cond = c3statement.do_condition('IpAddress,aws:SourceIp,**PUBLIC**')
    assert cond == {'IpAddress': {'aws:SourceIp': '0.0.0.0/0'}}
    cond = c3statement.do_condition(
        'StringEquals,s3:x-amz-acl,bucket-owner-full-control')
    assert cond == {
        'StringEquals': {'s3:x-amz-acl': 'bucket-owner-full-control'}}
    cond = c3statement.do_condition('invalid')
    assert cond == False
    cond = c3statement.do_condition('1,2,3,4')
    assert cond == False

class TestConfigExcpetions(object):
    ''' Test class for c3.utils.config exceptions '''
    def __init__(self):
        self.fake_ini = os.getcwd() + '/tests/fake/devpro.ini'
        self.bad_ini = os.getcwd() + '/tests/exceptions/devpro.ini'
        self.good_ini = os.getcwd() + '/tests/confs/devpro.ini'
        self.c3config = c3.utils.config

    def test_exception_invalid_config(self):
        ''' Testing ConfigNotFoundException exception '''
        with assert_raises(self.c3config.ConfigNotFoundException) as msg:
            self.c3config.ClusterConfig(
                ini_file=self.fake_ini, no_defaults=True)
        assert_equal(msg.exception.value, 'Invalid config: %s' % self.fake_ini)

    def test_exception_get_azs(self):
        ''' Test exception for get azs '''
        cconfig = self.c3config.ClusterConfig(
            ini_file=self.good_ini)
        with assert_raises(self.c3config.InvalidAZError) as msg:
            cconfig.set_azs('us-east-1aa')
        assert_equal(msg.exception.value, "AZ 'us-east-1aa' is invalid")

    def test_exception_too_many_amis(self):
        ''' Test exception for TooManyAMIsError '''
        with assert_raises(self.c3config.TooManyAMIsError) as msg:
            raise self.c3config.TooManyAMIsError('error')
        assert_equal(msg.exception.value, 'error')


class TestConfig(object):
    ''' testMatch class for c3.utils.config '''
    def __init__(self):
        mapfile = os.getcwd() + '/tests/confs/account_aliases_map.txt'
        os.environ['AWS_CONF_DIR'] = os.getcwd() + '/tests/confs'
        os.environ['AWS_BASE_DIR'] = os.getcwd() + '/tests'
        os.environ['HOME'] = os.getcwd() + '/tests/confs'
        self.config = os.getcwd() + '/tests/confs/devpro.ini'
        self.cconfig = c3.utils.config.ClusterConfig(
            ini_file=self.config, account_name='opsqa')
        self.config_func = c3.utils.config
        self.solo_cconfig = c3.utils.config.ClusterConfig(
            ini_file=self.config, account_name='opsqa', no_defaults=True)

    def test_get_account_from_conf(self):
        ''' Testing get account from conf function '''
        account = self.config_func.get_account_from_conf(conf=self.config)
        assert account == 'opsqa'
        account = self.config_func.get_account_from_conf(conf='fake.ini')
        assert account == None

    def test_get_hvm_instances(self):
        ''' Testing get hvm instances '''
        instances = self.config_func.get_hvm_instances()
        assert instances == [
            'cc2.8xlarge',
            'i2.xlarge',
            'i2.2xlarge',
            'i2.4xlarge',
            'i2.8xlarge',
            'r3.large',
            'r3.xlarge',
            'r3.2xlarge',
            'r3.4xlarge',
            'r3.8xlarge',
            't2.micro',
            't2.small',
            't2.medium',
        ]

    def test_verify_az(self):
        ''' Testing verify az function '''
        assert self.config_func.verify_az('us-east-1a')
        assert self.config_func.verify_az('us-east-1aa') == False

    def test_get_azs(self):
        ''' Testing get_ami method '''
        azs = self.cconfig.get_azs()
        assert azs == ['us-east-1a', 'us-east-1b', 'us-east-1c',
                       'us-east-1d', 'us-east-1e']
        self.cconfig.set_azs('us-east-1b,us-east-1c')
        azs = self.cconfig.get_azs()
        assert azs == ['us-east-1b', 'us-east-1c']

    def test_get_count(self):
        ''' Testing get_count method '''
        assert self.cconfig.get_count() == 1
        self.cconfig.set_count(7)
        assert self.cconfig.get_count() == 7

    def test_get_size(self):
        ''' Testing get size '''
        assert self.cconfig.get_size() == 't2.micro'
        self.cconfig.set_size('m7.huge')
        assert self.cconfig.get_size() == 'm7.huge'

    def test_get_ami(self):
        ''' Testing getting AMI '''
        assert self.cconfig.get_ami() == 'ami_centos'
        self.cconfig.set_ami('ami-wil') == 'ami-wil'
        assert self.cconfig.get_ami() == 'ami-wil'

    def test_get_resolved_ami(self):
        ''' Test get resolved ami exception '''
        with assert_raises(c3.utils.config.AMINotFoundError) as msg:
            self.cconfig.get_resolved_ami(nventory=None)
        assert_equal(msg.exception.value, "No AMI matching 'ami_centos' found")

    def test_get_count_azs(self):
        ''' Testing getting count of AZs'''
        self.cconfig.set_azs('us-east-1c,us-east-1b,us-east-1b')
        assert self.cconfig.get_count_azs() == 2

    def test_get_tagset(self):
        ''' Testing get tagset '''
        tagset = self.cconfig.get_tagset()
        assert tagset == {
            'BusinessUnit': 'CityGrid',
            'Project': 'CloudTest',
            'Component': 'pro ProvisionTestBox',
            'Env': 'dev',
            'Team': 'Operations'}

    def test_get_user_data(self):
        ''' Testing get user data file '''
        userdata = self.cconfig.get_user_data_file()
        expected_file = os.getcwd() + '/tests/bin/userdata.pl'
        if userdata == expected_file:
            pass
        else:
            assert False
        print >> sys.stdout, self.cconfig.get_user_data()
        assert self.cconfig.get_user_data() == 'MOCK'

    def test_get_additional_sgs(self):
        ''' Testing get additional SGs '''
        assert self.cconfig.get_additional_sgs() == ['ssg-management']
        self.cconfig.add_sg("sg-other")
        sgs = self.cconfig.get_additional_sgs()
        assert sgs == ['ssg-management', 'sg-other']

    def test_get_allocate_eips(self):
        ''' Testing get allocate EIPs '''
        assert self.cconfig.get_allocate_eips() == False
        self.cconfig.set_allocate_eips()
        assert self.cconfig.get_allocate_eips() == True

    def test_get_ebs_config(self):
        ''' Test get ebs config '''
        volumes = self.cconfig.get_ebs_config()
        assert volumes == [
            {
                'type': 'io1',
                'device': '/dev/sdf',
                'size': '500',
                'iops': '1000'
            },
            {
                'type': 'standard',
                'device': '/dev/sdg',
                'size': '500',
                'iops': None
            }
        ]
        ebs = self.config_func.EBSConfig()
        ebs.set_azs(['us-east-1a','us-east-1b'])
        assert ebs.get_azs() == ['us-east-1a', 'us-east-1b']

    def test_elb_config(self):
        ''' Test elb config class '''
        self.cconfig.elb.set_azs(['us-east-1a', 'us-east-1b'])
        assert self.cconfig.elb.get_azs() == ['us-east-1a', 'us-east-1b']
        assert self.cconfig.elb.validate() == True
        self.cconfig.elb.protocol = None
        assert self.cconfig.elb.validate() == False
        self.cconfig.elb.enabled = False
        assert self.cconfig.elb.validate() == False

    def test_sg_config(self):
        ''' Test sg config class '''
        cidrs = self.cconfig.sgrp.get_cidr()
        sgs = self.cconfig.sgrp.get_sg()
        assert cidrs == [
            {'cidr': '99.119.252.62/32', 'fport': 22,
             'lport': 22, 'proto': 'tcp'},
            {'cidr': '0.0.0.0/0', 'fport': -1,
             'lport': -1, 'proto': 'icmp'}]
        assert sgs == [
            {'fport': 22, 'lport': 22, 'owner': '123456789012',
             'proto': 'tcp', 'sg': 'devjmp'},
            {'fport': 22, 'lport': 22, 'owner': '210987654321',
             'proto': 'tcp', 'sg': 'prdjmp'},
            {'fport': 80, 'lport': 80, 'owner': 'amazon-elb',
             'proto': 'tcp', 'sg': 'amazon-elb-sg'}]

    def test_rds_sg_config(self):
        ''' Test RDS SG config class '''
        cidrs = self.cconfig.rds_sg.get_cidr()
        sgs = self.cconfig.rds_sg.get_sg()
        assert cidrs == [
            {'cidr': '111.111.111.39/27'}, {'cidr': '111.111.112.39/27'}]
        assert sgs == [
            {'oid': '210987654321', 'sid': 'prdjmp'}]

    def test_rds_pg_config(self):
        ''' Test RDS PG config class '''
        params = self.cconfig.rds_pg.get_parameters()
        assert params == [
            ('skip_name_resolve', '1', 'pending-reboot'),
            ('max_connect_errors', '999999999', 'immediate')]

    def test_rds_instance_config(self):
        ''' Test RDS instance config '''
        data = self.cconfig.rds.get_config()
        assert data == {
            'allocated_storage': '100', 'auto_minor_version_upgrade': 'True',
            'aws_base_dir': os.getenv('AWS_BASE_DIR'),
            'aws_conf_dir': os.getenv('AWS_CONF_DIR'),
            'backup_retention_period': '3', 'engine': 'mysql',
            'engine_version': '5.6.23', 'iops': None,
            'master_username': 'awsroot', 'multi_az': None,
            'preferred_backup_window': '00:00-05:00',
            'preferred_maintenance_window': 'sat:18:00-sat:22:00',
            'publicly_accessible': 'True'}

    def test_config_gets(self):
        ''' Test Cluster Config gets '''
        assert self.cconfig.get_primary_sg() == 'devpro'
        assert self.cconfig.get_global_ssg() == 'ssg-management'
        assert self.cconfig.get_aws_region() == 'us-east-1'
        assert self.cconfig.get_cg_region() == 'aws1'
        url = self.cconfig.get_whitelist_url()
        assert url == 'https://sqs.aws.com/210987654321/puppetmaster-whitelist'
        assert self.cconfig.raid.get_level() == '0'
        assert self.cconfig.raid.get_device() == 'EBS'
        assert self.cconfig.get_use_ebs_optimized() == False
        assert self.cconfig.get_node_groups() == ['default_install', 'pro']
        assert self.cconfig.get_sleep_step() == 10
        assert self.cconfig.get_launch_timeout() == 180
        assert self.cconfig.get_dc() == 'aws1'
        assert self.cconfig.get_count_azs() == 5
        assert self.cconfig.get_next_az() == 'us-east-1a'
        assert self.cconfig.get_sleep_step() == 10
        assert self.cconfig.get_additional_sgs() == ['ssg-management']
        assert self.cconfig.get_sgs() == ['ssg-management', 'devpro']
