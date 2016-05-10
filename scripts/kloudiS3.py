#!/usr/bin/python2.7
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
''' A tool that generates JSON policy objects from config files '''
import json
import os
import sys
import optparse
import kloudi.utils.config
from kloudi.utils.jgp import gen_entry
from kloudi.utils.jgp import statement
from kloudi.utils import accounts
from kloudi.aws.s3.bucket import KloudiS3Bucket
from zambi import ZambiConn


def gen_statement(entries):
    ''' Generates S3 bucket policy statments '''
    statements = []
    data = {}
    for entry in entries:
        (effect, action, user,
         user_acct, path, condition) = split_parameter(entry)
        statements.append(statement.make_statement(user_acct, user,
                                                   path, action,
                                                   effect, condition))
    data['Statement'] = statements
    return data


def to_json(data):
    ''' Converts data to JSON '''
    try:
        return json.dumps(data, indent=4, separators=(',', ': '))
    except Exception:
        raise


def split_parameter(entry):
    ''' Splits entry into multiple fields '''
    field = entry.split('|')
    return (field[0], field[1], field[2], field[3], field[4], field[5])


def generate_file(data, output_dir, account, bucket):
    ''' Dump JSON policy to a file '''
    json_file = ('%s/%s-%s.json' % (output_dir, account, bucket))
    print 'INFO: Saving JSON ouput to %s' % json_file
    conf = open(json_file, 'w')
    conf.write(data)
    conf.close()


def send_to_aws(data, account, bucket, tagset, verbose):
    ''' Creates a connection to AWS and sends data '''
    conn_manager = ZambiConn()
    conn = conn_manager.get_connection(account, service='s3')
    s3_bucket = KloudiS3Bucket(conn, bucket)
    print 'INFO: Updating %s:%s' % (account, bucket)
    print 'INFO: Setting tags'
    if verbose:
        print 'INFO: TAGS:\n%s' % tagset
    s3_bucket.set_tags(tagset, verbose)
    if data:
        print 'INFO: Setting bucket policy'
        if verbose:
            print 'INFO: JSON OUTPUT:\n%s' % data
            s3_bucket.upload_policy(data)
        else:
            s3_bucket.upload_policy(data)


def generate_entries(user, config):
    ''' Generates entries from config files '''
    ini = gen_entry.read_config(config)
    if 'cidr-networks' in user:
        acct_id = 'cidr-networks'
        user = 'cidr-networks'
    else:
        (user_acct, user) = user.split('-', 1)
        if user_acct.isdigit():
            acct_id = user_acct
        else:
            acct_id = accounts.get_account_id(user_acct)
    return gen_entry.gen_s3_entry(ini, user, acct_id)


def get_tags(config, verbose):
    ''' Get bucket cost tags from config '''
    cluster_config = kloudi.utils.config.ClusterConfig(
        ini_file=config,
        prv_type='s3',
        verbose=verbose,
        no_defaults=True)
    return cluster_config.get_tagset()


def parser_setup():
    ''' Setup the options parser '''
    usage = 'usage: %prog [options]'
    desc = 'Generate S3 bucket json policy'
    parser = optparse.OptionParser(usage=usage, description=desc)
    parser.add_option('--config-dir',
                      '-c',
                      action='store',
                      dest='config_dir',
                      type='string',
                      help='Policy config directory location')
    parser.add_option('--bucket',
                      '-b',
                      action='store',
                      dest='acct_bucket',
                      type='string',
                      help='S3 Bucket to update')
    parser.add_option('--output-dir',
                      '-o',
                      action='store',
                      dest='output_dir',
                      type='string',
                      help='Output dir to save json file for bucket')
    parser.add_option('--verbose',
                      '-v',
                      action='store_true',
                      default=False,
                      dest='verbose',
                      help='Enables verbose output')
    return parser


def main():
    ''' The main program executed '''
    parser = parser_setup()
    (options, args) = parser.parse_args()
    if args:
        parser.print_help()
        parser.error('Too many arguments')
    if options.config_dir is None or options.acct_bucket is None:
        parser.print_help()
        parser.error('CONFIG-DIR and BUCKET must be specified')
    (account, bucket) = options.acct_bucket.split('/')
    conf_files = next(os.walk(options.config_dir +
                              '/' + options.acct_bucket))[2]
    entries = list()
    for conf in conf_files:
        config = (options.config_dir + '/' + options.acct_bucket + '/' + conf)
        user = conf.split('.ini')[0]
        if user:
            if user == 'meta':
                tagset = get_tags(config, options.verbose)
            else:
                entries += generate_entries(user, config)
    if len(entries) == 0:
        policy = None
    else:
        policy = to_json(gen_statement(entries))
    if 'tagset' not in vars():
        print 'ERROR: Missing tags in meta.ini'
        sys.exit(1)
    if options.output_dir is None:
        send_to_aws(policy, account, bucket, tagset, options.verbose)
    else:
        generate_file(policy, options.output_dir, account, bucket)


if __name__ == '__main__':
    main()
