#!/usr/bin/python2.6
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
"""
Script to update Route53 with AWS hostnames found in nventory. Initially
works only on AWS hostnames (CNAMEs).
"""

import argparse
from zambi import ZambiConn
from nvlib import Nventory
from kloudi.utils.graphite import Graphite
from kloudi.aws.route53.hostedzone import HostedZone


class Nv2Route53(object):
    ''' Update Route53 with AWS hostnames in nventory. '''
    def __init__(self, options):
        self.options = options
        self.cmgr = ZambiConn()
        self.accounts = self.cmgr.get_accounts(self.options.aws_account)
        for self.account in self.accounts:
            self.dns = None
            self.update_records()
            if self.options.graphite:
                self.send_metrics()

    def send_metrics(self):
        ''' Send route53 metrics to graphite '''
        mpfx = 'business.aws.route53.%s' % self.account
        (creates, updates, count) = self.dns.get_metrics()
        grp = Graphite(server=self.options.graphite_server)
        grp.send_metric(mpfx + ".updates",
                       updates, self.options.debug)
        grp.send_metric(mpfx + ".creates",
                       creates, self.options.debug)
        grp.send_metric(mpfx + ".count",
                       count, self.options.debug)

    def update_records(self):
        ''' Run route53 updates based on nventory '''
        nvd = Nventory(ini_file=self.options.nv_ini)
        conn = self.cmgr.get_connection(self.account, service='route53')
        self.dns = HostedZone(conn, self.account, self.options.comment,
                              domain=self.options.domain)
        data = {
            'loc': '',
            'env': '',
            'sclass': '',
            'acct': self.account,
            'domain': self.options.domain}
        nodes = nvd.get_nodes(data)
        nvec2nodes = dict()
        for node in nodes:
            if node['name'] and node['ec2_instance_id']:
                nvec2nodes[node['name']] = {
                    'type': 'CNAME',
                    'ttl': self.options.ttl,
                    'resource': [node['ec2_public_hostname']]}
        if nvec2nodes:
            self.dns.add_update_records(
                nvec2nodes, record_type='CNAME', ttl=self.options.ttl)
        else:
            print 'INFO: No nodes found in external data source.'


def parser_setup():
    ''' Setup the options parser '''
    desc = 'Manages Route53 from external node classifier. '''
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-a',
                        action='store',
                        dest='aws_account',
                        help='Use AWS Account')
    parser.add_argument('-d',
                        action='store',
                        dest='domain',
                        help='Use domain, top level tld')
    parser.add_argument('-t',
                        action='store',
                        type=int,
                        dest='ttl',
                        default=60,
                        help='Set Route53 record ttl')
    parser.add_argument('-c',
                        action='store',
                        dest='comment',
                        default='Managed by kloudi-nv2route53.py',
                        help='Set Route53 record comment')
    parser.add_argument('-g',
                        action='store_true',
                        dest='graphite',
                        default=False,
                        help='Send output to graphite')
    parser.add_argument('-G',
                        action='store',
                        dest='graphite_server',
                        default='dev.relay-aws.graphite.ctgrd.com',
                        help='the graphite server to send to')
    parser.add_argument('-D',
                        action='store_true',
                        dest='debug',
                        default=False,
                        help="Print, but don't actually send anything")
    parser.add_argument(
        '-n',
        action='store',
        dest='nv_ini',
        default="/app/secrets/nv_prd.ini",
        help='External DB ini file to use; useful for testing')
    return parser


def main():
    ''' Setup options and call main program '''
    parser = parser_setup()
    options = parser.parse_args()
    Nv2Route53(options)


if __name__ == '__main__':
    main()
