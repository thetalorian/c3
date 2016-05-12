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
''' Generates JSON Statements for AWS policies '''
import sys
import ipaddr
import c3.utils.naming
from c3.utils import logging


def make_statement(user_acct, user, path, action,
                   effect, condition):
    ''' Generate JSON statement '''
    statement = {}
    statement['Action'] = do_action(action)
    statement['Resource'] = do_resource(path)
    statement['Effect'] = effect
    statement['Principal'] = do_principal(user_acct, user)
    if condition != 'empty':
        statement['Condition'] = do_condition(condition)
    return statement


def do_action(action):
    ''' Returns actions in JSON '''
    return action.split(',')


def do_principal(user_account, user):
    ''' Returns prinipcal in JSON '''
    item = dict()
    if user_account == 'cidr-networks':
        item['AWS'] = '*'
    elif user == 'root':
        item['AWS'] = (['arn:aws:iam::' +
                        str(user_account) +
                        ':root'])
    else:
        item['AWS'] = (['arn:aws:iam::' +
                        str(user_account) +
                        ':user/' + user])
    return item


def do_condition(condition):
    ''' Generate the condition block in the json
    condition is a three item string like:
    ConditionName,ConditionProperty,ConditionValue '''
    item = dict()
    if condition and len(condition.split(',')) == 3:
        (name, prop, value) = condition.split(',')
        item[name] = {}
        if is_ipnetwork(value):
            item[name][prop] = value
        elif c3.utils.naming.get_cidr(value):
            value = c3.utils.naming.get_cidr(value)
            item[name][prop] = value
        else:
            item[name][prop] = value
        return item
    elif condition == 'empty':
        pass
    else:
        logging.warn('Not enough values given to assign '
                              'condition in %s' % condition)
        return False


def do_resource(path):
    ''' Generate the resource block in the json (list of paths) '''
    resource = []
    resource.append('arn:aws:s3:::%s' % path)
    return resource


def is_ipnetwork(value):
    ''' Checks wether a given value is a valid IPv4 network, returns boolean '''
    try:
        ipaddr.IPNetwork(value)
        return True
    except ValueError:
        return False
