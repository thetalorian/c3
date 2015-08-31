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
''' This module Manages tagging '''
import os
import boto.s3.tagging
from c3.utils import logging
from boto.exception import EC2ResponseError


def get_validation_file(tname):
    ''' Return cost tags validation file '''
    return os.getenv('AWS_CONF_DIR') + '/cost_tags.' + tname

def validate_tag(tname, tvalue):
    ''' Check if the tag value is already allowed to avoid typos '''
    allowed = list()
    tag_file = get_validation_file(tname)
    # Component is an optional tag
    if tname == 'Component':
        return True
    try:
        tnfile = open(tag_file, 'r')
    except IOError, msg:
        logging.error(msg)
    for line in tnfile.readlines():
        allowed.append(line.strip())
    return tvalue in allowed


class Tagger(object):
    ''' C3 tagger object '''
    def __init__(self, conn, tagnames=None, verbose=False):
        self.conn = conn
        self.verbose = verbose
        self.prefix_cost = '/costs_tags.'
        if tagnames:
            self.tagnames = tagnames
        else:
            self.tagnames = [
                'BusinessUnit', 'Team', 'Project', 'Env', 'Component']

    def get_cost_tags_health(self, rid, tag_type=None):
        ''' Return cost tags for given resource '''
        tags = dict()
        if tag_type == "ec2" or rid[:2] == 'i-':
            instances = self.conn.get_all_instances([rid])
            instance = instances[0].instances[0]
            tags = instance.tags
        elif tag_type == 'ebs' or rid[:4] == 'vol-':
            vol = self.conn.get_all_volumes([rid])[0]
            tags = vol.tags
        return self.get_cost_tags_health_from_tags(tags)

    def get_cost_tags_health_from_tags(self, tags):
        ''' Check to ensure all required cost tags are healthy '''
        ret = dict()
        healthy = True
        for key in self.tagnames:
            try:
                ret[key] = tags[key]
            except KeyError, msg:
                logging.error('No key %s in tags' % msg)
                healthy = False
                ret[key] = None
        return healthy, ret

    def get_cost_tags(self, rid, tag_type=None):
        ''' Return cost tags '''
        healthy, ret = self.get_cost_tags_health(rid, tag_type=tag_type)
        logging.info('Retrived tags: %s Healhty: %s' % (ret, healthy))
        return ret

    def add_tags(self, rids, tagset, tag_type=None):
        ''' Set one or more tags on a list of IDs '''
        failed = 0
        for rid in rids:
            logging.debug('Tagging resource: %s' % rid, self.verbose)
            if not self._add_tags(rid, tagset, tag_type=tag_type):
                failed += 1
        if not failed:
            return True
        else:
            return False

    def _add_tags(self, rid, tagset, tag_type=None):
        ''' Set one or more tags on a single ID '''
        failed = 0
        if tag_type == 'ec2' or rid[:2] == 'i-':
            rid = self.conn.get_all_instances([rid])
            instance = rid[0].instances[0]
            for tname, tvalue in tagset.items():
                logging.info('For %s adding, %s: %s' %
                             (instance, tname, tvalue))
                try:
                    instance.add_tag(tname, tvalue)
                except EC2ResponseError, msg:
                    logging.error(msg.message)
                    failed += 1
            logging.info('Checking for attached EBS volumes')
            try:
                volumes = self.conn.get_all_volumes()
            except EC2ResponseError, msg:
                logging.error(msg.message)
                failed += 1
            for vol in volumes:
                if vol.attach_data.instance_id == instance.id:
                    logging.info('Found attached vol: %s' % vol.id)
                    self._add_tags(vol.id, tagset, tag_type='ebs')
        elif tag_type == 'ebs' or rid[:4] == 'vol-':
            try:
                vol = self.conn.get_all_volumes([rid])[0]
            except EC2ResponseError, msg:
                logging.error(msg.message)
                failed += 1
            for tname, tvalue in tagset.items():
                logging.info('For %s adding, %s:%s' % (vol.id, tname, tvalue))
                try:
                    vol.add_tag(tname, tvalue)
                except EC2ResponseError, msg:
                    logging.error(msg.message)
                    failed += 1
        elif tag_type == 'rds':
            return True
        else:
            return self.tag_s3_bucket(rid, tagset)
        if not failed:
            return True
        else:
            return False

    def tag_s3_bucket(self, rid, tagset):
        ''' Tags S3 buckets with complicated s3 tagging shenanigans '''
        used_tags = list()
        failed = 0
        logging.info('Tagging S3 bucket %s' % rid)
        try:
            bucket = self.conn.get_bucket(rid)
        except EC2ResponseError, msg:
            logging.error(msg.message)
            failed += 1
        try:
            existing_tags = bucket.get_tags()[0]
        except EC2ResponseError, msg:
            logging.error(msg.message)
            existing_tags = dict()
        logging.info('Existing tags: %s' % existing_tags)
        try:
            tags = boto.s3.tagging.Tags()
            tset = boto.s3.tagging.TagSet()
        except EC2ResponseError, msg:
            logging.error(msg.message)
            failed += 1
        for tname, tvalue in tagset.items():
            if tname not in used_tags:
                try:
                    tset.add_tag(tname, tvalue)
                    used_tags.append(tname)
                except EC2ResponseError, msg:
                    logging.error(msg.message)
                    failed += 1
            for tag in existing_tags:
                if tag.key not in used_tags:
                    logging.info('Tagging %s, %s: %s' %
                                 (rid, tag.key, tag.value))
                    try:
                        tset.add_tag(tag.key, tag.value)
                        used_tags.append(tag.key)
                    except EC2ResponseError, msg:
                        logging.error(msg.message)
                        failed += 1
            logging.info('Submitting tagset for S3 bucket')
            try:
                tags.add_tag_set(tset)
                bucket.set_tags(tags)
            except EC2ResponseError, msg:
                logging.error(msg.message)
                failed += 1
        if not failed:
            return True
        else:
            return False
