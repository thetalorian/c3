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

import re
import c3.utils.accounts
from c3.nvdb import NvDb


def find_available_hostnames(group, count=1, account=None,
                             region_or_az="us-east-1", domain=None):
    '''
    Return the first <count> appropriate hostnames not already in nventory
    '''
    retnodes = list()
    nodes = list()
    nvdb = NvDb()
    if account is None:
        return False
    data = {
        'loc': get_aws_dc(region_or_az),
        'env': group[:3],
        'sclass': group[3:],
        'acct': account,
        'domain': domain}
    node_data = nvdb.get_nodes(data)
    for node in node_data:
        nodes.append(node['name'])
    num = 1
    while num < 100:
        possible = gen_hostname(group, num, account, region_or_az, domain)
        if possible not in nodes:
            retnodes.append(possible)
        if len(retnodes) == count:
            return retnodes
        num += 1
    return None


def gen_hostname(group, num, account=None, region_or_az="us-east", domain=None):
    '''
    Return the CGM hostname if the SG uses the naming convention
    >>> gen_hostname("devweb", 1, "prod")
    'aws1devweb1.prod.ctgrd.com'
    >>> gen_hostname("prdpxy", 3, "prodweb")
    'aws1prdpxy3.prodweb.ctgrd.com'
    '''
    if domain is None:
        domain = "ctgrd.com"
    if re.search("^(prd|dev|prg|qat|sts|tst|utl|stg|sbx)[a-z][a-z][a-z]$",
                 group):
        return ("%s%s%d.%s.%s" %
                (get_aws_dc(region_or_az), group, num, account, domain))
    else:
        return False


def get_aws_dc(region_or_az):
    ''' Returns the CGM standard AWS datacenter. '''
    if re.match('us-east-1', region_or_az):
        return 'aws1'
    elif re.match('us-west-1', region_or_az):
        return 'aws2'
    elif re.match('eu-west-1', region_or_az):
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
