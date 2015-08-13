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


def make_statement(user_acct, user, path, action,
                   effect, condition):
    """
    Test 1
    >>> make_statement('086441151436','root',\
'cgm-cloudtrail/*','s3:GetBucketAcl','Allow', 'empty')
    {'Action': ['s3:GetBucketAcl'], 'Resource': \
['arn:aws:s3:::cgm-cloudtrail/*'], \
'Effect': 'Allow', \
'Principal': {'AWS': ['arn:aws:iam::086441151436:root']}}
    >>> make_statement('086441151436','root',\
'cgm-cloudtrail/AWSLogs/150620942615/*','s3:PutObject','Allow','StringEquals,\
s3:x-amz-acl,bucket-owner-full-control')
    {'Action': ['s3:PutObject'], 'Resource': \
['arn:aws:s3:::cgm-cloudtrail/AWSLogs/150620942615/*'], \
'Effect': 'Allow', 'Condition': {'StringEquals': {'s3:x-amz-acl': \
'bucket-owner-full-control'}}, \
'Principal': {'AWS': ['arn:aws:iam::086441151436:root']}}
    """
    statement = {}
    statement['Action'] = do_action(action)
    statement['Resource'] = do_resource(path)
    statement['Effect'] = effect
    statement['Principal'] = do_principal(user_acct, user)
    if condition != 'empty':
        statement['Condition'] = do_condition(condition)
    return statement


def do_action(action):
    """
    Test 1
    >>> do_action('s3:get*,s3:list*')
    ['s3:get*', 's3:list*']

    Test 2
    >>> do_action('s3:GetBucketAcl')
    ['s3:GetBucketAcl']
    """
    return action.split(',')


def do_principal(user_account, user):
    """
    Test cidr
    >>> do_principal('cidr-networks','')
    {'AWS': '*'}

    Test root user
    >>> do_principal('blah','root')
    {'AWS': ['arn:aws:iam::blah:root']}

    Test general user
    >>> do_principal('blah','user')
    {'AWS': ['arn:aws:iam::blah:user/user']}
    """
    item = {}
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
    """Generate the condition block in the json
    condition is a three item string like
    'ConditionName,ConditionProperty,ConditionValue'

    Test some valid conditions
    >>> do_condition('IpAddress,aws:SourceIp,216.1.187.128/27')
    {'IpAddress': {'aws:SourceIp': '216.1.187.128/27'}}
    >>> do_condition('StringEquals,s3:x-amz-acl,bucket-owner-full-control')
    {'StringEquals': {'s3:x-amz-acl': 'bucket-owner-full-control'}}

    Test wrong item number
    >>> do_condition('invalid')
    False
    >>> do_condition('1,2,3,4')
    False
    """
    item = {}
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
        print >> sys.stderr, ('WARNING: Not enough values given to assign '
                              'condition in %s' % condition)
        return False


def do_resource(path):
    """Generate the resource block in the json (list of paths)

    Test some valid conditions
    >>> do_resource('bucketname/*')
    ['arn:aws:s3:::bucketname/*']
    >>> do_resource('mybucket/some/path/in/my/bucket')
    ['arn:aws:s3:::mybucket/some/path/in/my/bucket']
    """
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

if __name__ == "__main__":
    import doctest
    doctest.testmod()
