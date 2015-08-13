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
''' A module to interface with nVentory, an external data source. '''

import re
import sys
import json
import urllib
import urllib2
import ConfigParser
import xml.etree.ElementTree as ET
from cookielib import CookieJar


def verbose_msg(message, verbose):
    ''' Function for verbose output. '''
    if verbose:
        print 'DEBUG: %s' % message


def error_msg(message):
    ''' Print error message to sys.stderr '''
    print >> sys.stderr, 'ERROR: %s' % message


def build_query(data):
    ''' Given cgm specific arguments, build an nv query. '''
    query = 'regex_name='
    wild = '.*'
    if data['loc']:
        query += data['loc']
    if data['env']:
        query += data['env']
    elif wild not in query:
        query += wild
    if data['sclass']:
        sclass = data['sclass'] + wild
        query += sclass
    elif wild not in query:
        query += wild
    if data['acct']:
        acct = '.' + data['acct']
        query += acct
    elif wild not in query:
        query += wild
    if data['domain']:
        domain = '.' + data['domain']
        query += domain
    return query


class NvDb(object):
    ''' Represents a connection to the nventory DB. '''
    def __init__(self, ini_file=None, verbose=False):
        self.url = None
        self.user = None
        self.passwd = None
        self.verbose = verbose
        self.default_hardware_profile_id = None
        self.default_status = None
        if ini_file is not None:
            self.read_ini(ini_file)
        else:
            self.url = 'http://nventory.ctgrd.com'
        self.cookiejar = CookieJar()

    def read_ini(self, ini_file):
        ''' Read nventory configuration information from an ini file '''
        ini = ConfigParser.ConfigParser()
        if ini.read(ini_file):
            try:
                self.user = ini.get('nv', 'user')
            except ConfigParser.NoOptionError, msg:
                error_msg(msg)
            try:
                self.passwd = ini.get('nv', 'pass')
            except ConfigParser.NoOptionError, msg:
                error_msg(msg)
            try:
                self.url = ini.get('nv', 'url')
            except ConfigParser.NoOptionError, msg:
                error_msg(msg)
            try:
                self.default_hardware_profile_id = ini.get(
                    'nv', 'hardware_profile_id')
            except ConfigParser.NoOptionError, msg:
                error_msg(msg)
            try:
                self.default_status = ini.get('nv', 'status')
            except ConfigParser.NoOptionError, msg:
                error_msg(msg)
        else:
            error_msg('Failed to read %s' % ini_file)
            return False

    def get_nodes(self, data):
        ''' Get a dict of nodes based on search criteria. '''
        return self.query(build_query(data))

    def get_node_by_instance_id(self, uid):
        ''' Returns a node based on the given instance id. '''
        query = "uniqueid=%s" % uid
        return self.query(query)

    def login(self):
        ''' Established a login to nVentory for write operations. '''
        encoded = urllib.urlencode(
            {"login": self.user, "password": self.passwd})
        opener = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(self.cookiejar))
        url = self.url.replace("http://", "https://") + "login/login"
        rtc = opener.open(url, encoded)
        code = rtc.getcode()
        if code == 200:
            pat = re.compile("login/logout")
            if pat.search(rtc.read()):
                return True

    def add_node_groups(self, uid, nodegroups):
        ''' Add a list of nodegroups to a uniqueid. '''
        success = list()
        for nodegroup in nodegroups:
            if self.add_node_group(uid, nodegroup):
                success.append(nodegroup)
        return success

    def add_node_group(self, uid, nodegroup):
        ''' Add a single nodegroup to a uniqueid. '''
        ngid = self.get_node_group_id(nodegroup)
        if ngid:
            nodeid = self.query("uniqueid=%s" % uid)[0]['id']
            if nodeid:
                data = {"node_group_node_assignment[node_group_id]": ngid,
                        "node_group_node_assignment[node_id]": nodeid}
                encoded = urllib.urlencode(data)
                url = self.url + "node_group_node_assignments.xml"
                return self._submit(url, encoded)
            else:
                return False

    def register_host(self, hostname, uid, hw_profile_id=None):
        '''
        >>> dbrw.login()
        True
        >>> host="my5.fake.host"
        >>> uid="fake_unique_id_for_testing2"
        >>> dbrw.register_host(host, uid)
        True
        >>> nodes=dbrw.query("uniqueid=%s" % uid)
        >>> dbrw.add_node_groups(uid, ["test1", "paw", "bogus"])
        ['paw']
        >>> dbrw.delete(nodes[0]['id'])
        True
        '''
        if not hw_profile_id:
            hw_profile_id = self.default_hardware_profile_id
        data = {"node[name]": hostname,
                "node[hardware_profile_id]": hw_profile_id,
                "status[name]": self.default_status, "node[uniqueid]": uid}
        encoded = urllib.urlencode(data)
        url = self.url + "nodes.xml"
        verbose_msg('submitting: %s, %s' % (url, encoded), self.verbose)
        return self._submit(url, encoded)

    def update_rds_uid(self, hostname, uid):
        ''' Updates rds uid and status. '''
        opener = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(self.cookiejar))
        node = self.query("uniqueid=%s" % hostname)
        node_id = node[0]['id']
        data = {'format': 'xml',
                '_method': 'put',
                'id': node_id,
                'controller': 'nodes',
                'node[uniqueid]': uid,
                'status[name]': 'setup'}
        encoded = urllib.urlencode(data)
        url = self.url + 'nodes/%d.xml' % node_id
        verbose_msg('Submitting: %s%s' % (url, encoded), self.verbose)
        try:
            rtc = opener.open(url, encoded)
        except urllib2.HTTPError, msg:
            message = (
                "Couldn't update host %s with uid %s and status %s (%s))" %
                (hostname, uid, data['status[name]'], msg))
            error_msg(message)
            return False
        code = rtc.getcode()
        verbose_msg('Return code: %s' % code, self.verbose)
        if code == 200:
            return True
        return False

    def get_hwp_id(self, hostname):
        ''' Get the current Hardware profile ID from a node. '''
        data = "exact_name=%s" % hostname
        root = self.query_xml(data, "nodes.xml")
        try:
            return root.find('node').find('hardware_profile_id').text
        except AttributeError, msg:
            error_msg(msg)
            return None

    def set_status(self, ec2_id, status):
        ''' Set the status of an AWS instance. '''
        opener = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(self.cookiejar))
        node = self.query("uniqueid=%s" % ec2_id)
        node_id = node[0]['id']
        data = {'format': 'xml',
                '_method': 'put',
                'id': node_id,
                'controller': 'nodes',
                'status[name]': status}
        encoded = urllib.urlencode(data)
        url = self.url + 'nodes/%d.xml' % node_id
        verbose_msg('Submitting: %s%s' % (url, encoded), self.verbose)
        try:
            rtc = opener.open(url, encoded)
        except urllib2.HTTPError, msg:
            message = (
                "Couldn't update host %s with status %s (%s)" %
                (ec2_id, status, msg))
            error_msg(message)
            return False
        code = rtc.getcode()
        verbose_msg('Return code: %s' % code, self.verbose)
        if code == 200:
            return True
        return False

    def get_node_group_id(self, nodegroup):
        ''' Return a node group ID. '''
        data = "exact_name=%s" % nodegroup
        root = self.query_xml(data, "node_groups.xml")
        try:
            for ngrp in root.findall('node_group'):
                if ngrp.find('name').text == nodegroup:
                    return int(ngrp.find('id').text)
        except AttributeError, msg:
            error_msg(msg)
            return None

    def _submit(self, url, data):
        ''' Sumbit data to the nVentory API. '''
        opener = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(self.cookiejar))
        try:
            rtc = opener.open(url, data)
        except urllib2.HTTPError, msg:
            message = 'Submission of %s to %s failed. (%s)' % (data, url, msg)
            error_msg(message)
            return False
        code = rtc.getcode()
        if code == 201:
            return True
        elif code == 200:
            resp = rtc.read()
            if resp == " ":
                return True
            else:
                msg = "Register_host(): response wasn't as expected"
                error_msg(msg)
                msg = "nVentory returned: %s" % resp
                error_msg(msg)
                return False
        else:
            msg = 'Register_host(): response code was %d' % code
            error_msg(msg)
            return False

    def delete(self, uid):
        ''' Delete a node by it's nVentory id '''
        opener = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(self.cookiejar))
        data = {"_method": "delete"}
        encoded = urllib.urlencode(data)
        url = self.url + "nodes/%d" % uid
        try:
            rtc = opener.open(url, encoded)
        except urllib2.HTTPError, msg:
            message = "Couldn't delete host %s (%s)" % (uid, msg)
            error_msg(message)
            return False
        code = rtc.getcode()
        if code == 200:
            return True
        else:
            return False

    def get_ami(self, loc, name):
        '''
        Return a dict containing a single AMI
        >>> dbr.get_ami("aws1", "ami_centos_hvm_6.2") # doctest: +ELLIPSIS
        {'ami_centos_hvm_...
        '''
        ret = self.get_amis(loc, name)
        if len(ret) == 1:
            return ret
        else:
            return False

    def get_amis(self, loc, name):
        '''
        Return a dict of AMIs matching the name (not exact match)
        >>> dbr.get_amis("aws1", "ami_centos_hvm_6.2") # doctest: +ELLIPSIS
        {'ami_centos_hvm_...
        >>> dbr.get_amis("aws1", "centos") # doctest: +ELLIPSIS
        {'ami_centos...
        >>> dbr.get_amis("aws1", "ami_windows_3.11")
        {}
        '''
        query = "graffitis[name]=%s&exact_name=%s" % (name, loc)
        root = self.query_xml(query, 'node_groups.xml')
        if not root:
            msg = 'Query failed looking for  %s in %s' % (name, loc)
            return None
        ret = {}
        try:
            for ngrp in root.findall('node_group'):
                for grfs in ngrp.findall('graffitis'):
                    for grf in grfs.findall('graffiti'):
                        ret[grf.find('name').text] = grf.find('value').text
        except AttributeError, msg:
            message = 'Did not find %s in XML for %s (%s)' % (name, loc, msg)
            error_msg(message)
            return None
        if len(ret) == 0:
            msg = "Did not find %s in XML for %s" % (name, loc)
            error_msg(msg)
            return False
        return ret

    def query_xml(self, query, endpoint='node_groups.xml'):
        ''' Return an element tree of the result
        ** uses urllib2 and Element Tree libraries ** '''
        rurl = "%s%s?%s" % (self.url, endpoint, query)
        try:
            rtc = urllib2.urlopen(rurl)
        except urllib2.HTTPError, msg:
            message = (
                'Unable to contact nventory server: %s (%s)' %
                (self.url, msg))
            error_msg(message)
        root = ET.fromstring(rtc.read())
        return root

    def query(self, query, endpoint='nodes.json'):
        ''' Return a dict of nodes based on a raw nventory query
        ** uses urllib2 and json libraries **
        '''
        rurl = "%s%s?%s" % (self.url, endpoint, query)
        try:
            rtc = urllib2.urlopen(rurl + '&exclude_status[name]=decom')
        except urllib2.HTTPError, msg:
            message = (
                'Unable to contact nventory server: %s (%s)' %
                (self.url, msg))
            error_msg(message)
            return None
        if rtc.code != 200:
            return None
        if endpoint != 'nodes.json':
            print rurl + '&exclude_status[name]=decom'
            print rtc.read()
        try:
            return json.loads(rtc.read())
        except TypeError, msg:
            error_msg(msg)
            return None

if __name__ == '__main__':
    import doctest
    QAT_INI = "/app/secrets/nv_qat.ini"
    doctest.testmod(extraglobs={'dbr': NvDb(), 'dbrw': NvDb(ini_file=QAT_INI)})
