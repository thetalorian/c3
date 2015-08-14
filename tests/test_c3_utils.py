''' Tests for c3.utils '''

import os
import sys
import c3.utils.accounts


def test_invalid_get_account_name():
    ''' Test invalid get_account_name function. '''
    os.environ['AWS_ACCOUNT_ID'] = '123456789011'
    mapfile = os.getcwd() + '/tests/account_aliases_map.txt'
    account = c3.utils.accounts.get_account_name(mapfile=mapfile)
    assert account == None


def test_empty_get_account_name():
    ''' Test no account_id and OS env AWS_ACCOUNT_ID. '''
    os.environ['AWS_ACCOUNT_ID'] = ''
    assert c3.utils.accounts.get_account_name() == False


def test_get_account_name():
    ''' Test get_account_name function. '''
    os.environ['AWS_ACCOUNT_ID'] = '123456789012'
    mapfile = os.getcwd() + '/tests/account_aliases_map.txt'
    account = c3.utils.accounts.get_account_name(mapfile=mapfile)
    assert account == 'opsqa'


def test_invalid_get_account_id():
    ''' Test invalid get_account_id function. '''
    mapfile = os.getcwd() + '/tests/account_aliases_map.txt'
    account = c3.utils.accounts.get_account_id(
        account_name='opsprod', mapfile=mapfile)
    assert account == None


def test_env_get_account_id():
    ''' Test invalid get_account_id function. '''
    os.environ['AWS_ACCOUNT_ID'] == '123456789012'
    account = c3.utils.accounts.get_account_id()
    assert account == '123456789012'


def test_get_account_id():
    ''' Test get_account_id function. '''
    mapfile = os.getcwd() + '/tests/account_aliases_map.txt'
    account = c3.utils.accounts.get_account_id(
        account_name='opsqa', mapfile=mapfile)
    assert account == '123456789012'


def test_invalid_translate_account():
    ''' Test translate_account function. '''
    mapfile = os.getcwd() + '/tests/account_aliases_map_FAKE.txt'
    assert c3.utils.accounts.translate_account(mapfile=mapfile) == False
