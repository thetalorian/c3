''' Tests for c3.utils '''

import os
import c3.utils.accounts


def test_get_account_name():
    ''' Test function in c3.utils.accounts '''
    os.environ['AWS_ACCOUNT_ID'] = '123456789011'
    mapfile = os.getcwd() + '/tests/account_aliases_map.txt'
    account = c3.utils.accounts.get_account_name(mapfile=mapfile)
    assert account == None
    os.environ['AWS_ACCOUNT_ID'] = ''
    assert c3.utils.accounts.get_account_name() == False
    os.environ['AWS_ACCOUNT_ID'] = '123456789012'
    account = c3.utils.accounts.get_account_name(mapfile=mapfile)
    assert account == 'opsqa'


def test_get_account_id():
    ''' Test function in c3.utils.accounts '''
    mapfile = os.getcwd() + '/tests/account_aliases_map.txt'
    account = c3.utils.accounts.get_account_id(
        account_name='opsprod', mapfile=mapfile)
    assert account == None
    os.environ['AWS_ACCOUNT_ID'] == '123456789012'
    account = c3.utils.accounts.get_account_id()
    assert account == '123456789012'
    account = c3.utils.accounts.get_account_id(
        account_name='opsqa', mapfile=mapfile)
    assert account == '123456789012'


def test_translate_account():
    ''' Test function in c3.utils.accounts '''
    mapfile = os.getcwd() + '/tests/account_aliases_map_FAKE.txt'
    assert c3.utils.accounts.translate_account(mapfile=mapfile) == False
    os.environ['AWS_CONF_DIR']= os.getcwd() + '/tests'
    name = c3.utils.accounts.translate_account(account_id='123456789012')
    assert name == 'opsqa'
