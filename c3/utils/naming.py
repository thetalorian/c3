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
'''
Library for CGM naming conventions
'''

import os
import re
import sys
import c3.utils.accounts
from nvlib import Nventory
from c3.utils import logging


def find_available_hostnames(group, count=1, account=None,
                             region=None, domain=None, node_db=None):
    '''
    Return the first <count> appropriate hostnames not already in node_db
    '''
    retnodes = list()
    nodes = list()
    if node_db is None:
        node_db = Nventory(url='http://fakehost')
    if account is None:
        return False
    data = {
        'loc': get_aws_dc(region),
        'env': group[:3],
        'sclass': group[3:],
        'acct': account,
        'domain': domain}
    node_data = node_db.get_nodes(data)
    if node_data:
        for node in node_data:
            nodes.append(node['name'])
    num = 1
    while len(retnodes) != count:
        possible = gen_hostname(group, num, account, region, domain)
        if possible not in nodes:
            retnodes.append(possible)
        num += 1
    return retnodes


def gen_hostname(group, num, account=None, region="us-east-1", domain=None):
    ''' Return the CGM hostname if the SG uses the naming convention '''
    if domain is None:
        domain = "ctgrd.com"
    if re.search("^(prd|dev|prg|qat|sts|tst|utl|stg|sbx)[a-z][a-z][a-z]$",
                 group):
        return ("%s%s%d.%s.%s" %
                (get_aws_dc(region), group, num, account, domain))
    else:
        return False


def get_aws_dc(region):
    ''' Returns the CGM standard AWS datacenter. '''
    if re.match('us-east-1', region):
        return 'aws1'
    elif re.match('us-west-1', region):
        return 'aws2'
    elif re.match('eu-west-1', region):
        return "aws3"
    else:
        return False


def get_logging_bucket_name(account_id=None):
    '''
    Get the standardized bucket name for account_id or the current env account
    '''
    account_name = c3.utils.accounts.get_account_name(
        account_id=account_id)
    if account_name:
        return "cgs3log-%s" % account_name
    else:
        return False


def get_cidr(net):
    ''' Get the CIDR address from a network name '''
    names = get_network_data()[1]
    try:
        return names[net]
    except KeyError:
        pass


def get_network_data():
    ''' Parse the network file for use by other methods '''
    nets = dict()
    names = dict()
    net_file = '%s/%s' % (os.getenv('AWS_CONF_DIR'), '/networks.txt')
    try:
        nfile = open(net_file, 'r')
    except IOError, msg:
        logging.error(msg)
        return False
    for line in nfile.readlines():
        ent = line.strip().split(":")
        nets[ent[0]] = ent[1]
        names[ent[1]] = ent[0]
    return nets, names
