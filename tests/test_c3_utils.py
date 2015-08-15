''' Tests for c3.utils '''

import os
import sys
import c3.utils.accounts as c3accounts
import c3.utils.naming as c3naming


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
