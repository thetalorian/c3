''' Tests for c3.utils '''

import os
import sys
import random
import c3.utils.accounts as c3accounts
import c3.utils.naming as c3naming
import c3.utils.jgp.gen_entry as c3gen_entry
import c3.utils.jgp.statement as c3statement
import c3.utils.graphite


def test_get_account_name():
    ''' Test function in c3accounts'''
    os.environ['AWS_ACCOUNT_ID'] = '123456789011'
    mapfile = os.getcwd() + '/tests/account_aliases_map.txt'
    account = c3accounts.get_account_name(mapfile=mapfile)
    assert account == None
    os.environ['AWS_ACCOUNT_ID'] = ''
    assert c3accounts.get_account_name() == False
    os.environ['AWS_ACCOUNT_ID'] = '123456789012'
    account = c3accounts.get_account_name(mapfile=mapfile)
    assert account == 'opsqa'


def test_get_account_id():
    ''' Test function in c3accounts'''
    mapfile = os.getcwd() + '/tests/account_aliases_map.txt'
    account = c3accounts.get_account_id(
        account_name='opsprod', mapfile=mapfile)
    assert account == None
    os.environ['AWS_ACCOUNT_ID'] == '123456789012'
    account = c3accounts.get_account_id()
    assert account == '123456789012'
    account = c3accounts.get_account_id(
        account_name='opsqa', mapfile=mapfile)
    assert account == '123456789012'


def test_translate_account():
    ''' Test function in c3accounts'''
    mapfile = os.getcwd() + '/tests/account_aliases_map_FAKE.txt'
    assert c3accounts.translate_account(mapfile=mapfile) == False
    os.environ['AWS_CONF_DIR']= os.getcwd() + '/tests'
    name = c3accounts.translate_account(account_id='123456789012')
    assert name == 'opsqa'


def test_find_available_hostnames():
    ''' Test function in c3.utils.naming '''
    hosts = c3naming.find_available_hostnames(
        'devweb', count=2)
    assert hosts == False
    hosts = c3naming.find_available_hostnames(
        'devweb', count=2, account='opsqa', domain='ctgrd.com')
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
    os.environ['AWS_CONF_DIR'] = os.getcwd() + '/tests'
    bucket = c3naming.get_logging_bucket_name(account_id='123456789012')
    assert bucket == 'cgs3log-opsqa'
    bucket = c3naming.get_logging_bucket_name(account_id='123456789011')
    assert bucket == False


def test_get_cidr():
    ''' Test get_cidr function in c3.utils.naming '''
    os.environ['AWS_CONF_DIR'] = os.getcwd() + '/tests'
    cidr = c3naming.get_cidr('**PUBLIC**')
    assert cidr == '0.0.0.0/0'


def test_jgp_read_config():
    ''' Test read_config in c3.utils.jgp '''
    config = 'fake.ini'
    assert c3gen_entry.read_config(config) == False
    config = os.getcwd() + '/tests/opsqa-devzzz.ini'
    ini = c3gen_entry.read_config(config)
    assert ini.sections() == ['s3:get*,s3:list*', 's3:*',
                              's3:putObject', 's3:badtest']


def test_jgp_gen_s3_entry():
    ''' Test gen_s3_entry in c3.utils.jgp '''
    config = os.getcwd() + '/tests/opsqa-devzzz.ini'
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
