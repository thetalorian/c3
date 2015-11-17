''' Manage route53 hosted zones '''
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
import re
from boto.route53 import exception
from boto.route53.record import ResourceRecordSets


def verbose_msg(message, verbose):
    ''' Function for verbose output. '''
    if verbose:
        print 'DEBUG: %s' % message


class ZoneMetrics(object):
    ''' Class to gather route53 metrics '''
    def __init__(self):
        self.updates = 0
        self.creates = 0
        self.count = 0

    def metric_count(self, metric):
        ''' Increment metric count. '''
        if metric == 'updates':
            self.updates += 1
        if metric == 'creates':
            self.creates += 1

    def get_metrics(self):
        ''' Returns route53 metrics '''
        return (self.creates, self.updates)


class HostedZone(object):
    ''' Class to manage a route53 domain '''
    def __init__(self, conn, account, comment=None,
                 domain="ctgrd.com", verbose=False):
        self.conn = conn
        self.domain = "%s.%s" % (account, domain)
        self.comment = comment
        self.verbose = verbose
        self.zone_id = self.get_zone_id(self.domain)
        self.re_uqdn = re.compile("." + self.domain + ".?$")
        self.changes = ResourceRecordSets(
            self.conn, self.zone_id, self.comment)
        self.metrics = ZoneMetrics()

    def get_zone_id(self, domain):
        ''' Returns the zone id for the given domain.
        >>> dns.zone_id
        u'Z35T6NURAMOZT5'
        '''
        zones = self.conn.get_all_hosted_zones()
        domain = domain + '.'
        for zone in zones['ListHostedZonesResponse']['HostedZones']:
            msg = 'Found zone: %s' % zone['Name']
            verbose_msg(msg, self.verbose)
            if zone['Name'] == domain:
                msg = ('Using zone: %s domain: %s zoneId: %s' %
                       (zone['Name'], domain, zone['Id'].split('/')[2]))
                verbose_msg(msg, self.verbose)
                return zone['Id'].split("/")[2]
        print "ERROR Couldn't find domain %s" % domain
        return None

    def get_fqdn(self, name):
        ''' Retruns the FQDN for the host name given.
        >>> dns.get_fqdn('faketest1')
        'faketest1.opsqa.ctgrd.com'
        >>> dns.get_fqdn('faketest2.opsqa.ctgrd.com')
        'faketest2.opsqa.ctgrd.com'
        '''
        if self.domain == name[-len(self.domain):]:
            return name
        else:
            return "%s.%s" % (name, self.domain)

    def add_record(self, name, record):
        ''' Prepares to add new records.
        >>> dns.changes.changes = list()
        >>> nodes = dict()
        >>> nodes['faketest1.opsqa.ctgrd.com'] = {'type': 'CNAME',
        ...                                       'ttl': 60,
        ...                                       'resource': ['dummyhost1']}
        >>> nodes['faketest2.opsqa.ctgrd.com'] = {'type': 'CNAME',
        ...                                       'ttl': 60,
        ...                                       'resource': ['dummyhost2']}
        >>> dns.add_record('faketest1', nodes['faketest1.opsqa.ctgrd.com'])
        >>> dns.add_record('faketest2', nodes['faketest2.opsqa.ctgrd.com'])
        >>> dns.changes.changes
        [['CREATE', <Record:faketest1.opsqa.ctgrd.com:CNAME:dummyhost1>], \
['CREATE', <Record:faketest2.opsqa.ctgrd.com:CNAME:dummyhost2>]]
        '''
        if self.zone_id is None:
            print "Zone ID not set"
            return False
        change = self.changes.add_change(
            "CREATE", self.get_fqdn(name), record['type'], record['ttl'])
        for rec in record['resource']:
            change.add_value(rec)
        verbose_msg('Added record: %s' % change, self.verbose)
        self.metrics.metric_count('creates')

    def delete_record(self, name, record):
        ''' Prepares to delete existing records.
        >>> dns.changes.changes = list()
        >>> nodes = dict()
        >>> nodes['faketest1.opsqa.ctgrd.com'] = {'type': 'CNAME',
        ...                                       'ttl': 60,
        ...                                       'resource': ['dummyhost1']}
        >>> nodes['faketest2.opsqa.ctgrd.com'] = {'type': 'CNAME',
        ...                                       'ttl': 60,
        ...                                       'resource': ['dummyhost2']}
        >>> dns.delete_record('faketest1', nodes['faketest1.opsqa.ctgrd.com'])
        >>> dns.delete_record('faketest2', nodes['faketest2.opsqa.ctgrd.com'])
        >>> dns.changes.changes
        [['DELETE', <Record:faketest1.opsqa.ctgrd.com:CNAME:dummyhost1>], \
['DELETE', <Record:faketest2.opsqa.ctgrd.com:CNAME:dummyhost2>]]
        '''
        if self.zone_id is None:
            print "Zone ID not set"
            return False
        change = self.changes.add_change(
            "DELETE", self.get_fqdn(name), record['type'], record['ttl'])
        for rec in record['resource']:
            change.add_value(rec)

    def update_record(self, name, record):
        ''' Prepares to update existing records.
        >>> dns.changes.changes = list()
        >>> nodes = dict()
        >>> nodes['faketest1.opsqa.ctgrd.com'] = {'type': 'CNAME',
        ...                                       'ttl': 60,
        ...                                       'resource': ['dummyhost1']}
        >>> nodes['faketest2.opsqa.ctgrd.com'] = {'type': 'CNAME',
        ...                                       'ttl': 60,
        ...                                       'resource': ['dummyhost2']}
        >>> dns.update_record('faketest1', nodes['faketest1.opsqa.ctgrd.com'])
        >>> dns.update_record('faketest2', nodes['faketest2.opsqa.ctgrd.com'])
        >>> dns.changes.changes
        [['UPSERT', <Record:faketest1.opsqa.ctgrd.com:CNAME:dummyhost1>], \
['UPSERT', <Record:faketest2.opsqa.ctgrd.com:CNAME:dummyhost2>]]
        '''
        if self.zone_id is None:
            print "Zone ID not set"
            return False
        change = self.changes.add_change(
            "UPSERT", self.get_fqdn(name), record['type'], record['ttl'])
        for rec in record['resource']:
            change.add_value(rec)
        self.metrics.metric_count('updates')

    def commit_records(self):
        ''' Commit route53 records to aws API. '''
        msg = 'Submitted Records:\n\t%s ' % self.changes.changes
        verbose_msg(msg, self.verbose)
        try:
            self.changes.commit()
            return True
        except exception.DNSServerError, error:
            print 'ERROR: %s' % error.message
            return False

    def add_update_records(self, nodes, record_type=None, ttl=60):
        ''' Batch CREATE and UPSERT Route53 records.
        >>> dns.changes.changes = list()
        >>> nodes = dict()
        >>> nodes['faketest1.opsqa.ctgrd.com'] = {'type': 'CNAME',
        ...                                       'ttl': 60,
        ...                                       'resource': ['dummyhost1']}
        >>> nodes['faketest2.opsqa.ctgrd.com'] = {'type': 'CNAME',
        ...                                       'ttl': 60,
        ...                                       'resource': ['dummyhost2']}
        '''
        #>>> dns.add_update_records(nodes, record_type='CNAME', ttl=60)
        #True
        (exrecords, nrecords, del_records) = self.generate_records(
            nodes, record_type=record_type, ttl=ttl)
        if exrecords:
            print 'INFO: Records that match route53: %s' % len(exrecords)
            for name in exrecords:
                ovalue = exrecords[name]['resource']
                value = nodes[name.strip('.')]['resource']
                if ovalue != value:
                    print ("INFO: Updating, %s: %s" %
                           (name, nodes[name.strip('.')]))
                    self.update_record(name.strip('.'), nodes[name.strip('.')])
        if nrecords:
            print 'INFO: New records: %s' % len(nrecords)
            for name in nrecords:
                print "INFO: Adding %s: %s" % (name, nrecords[name]['resource'])
                self.add_record(name.strip('.'), nrecords[name])
        if del_records:
            print 'INFO: Record(s) to delete: %s' % len(del_records)
            for name in del_records:
                print 'INFO: To Delete: %s: %s' % (name, del_records[name])
        if len(self.changes.changes) != 0:
            print 'INFO: Submitting record changes to route53'
            return self.commit_records()
        else:
            print 'INFO: No changes to be made for: %s' % self.domain
            return False

    def get_metrics(self):
        ''' Return route53 metrics
        >>> dns.get_metrics() # doctest: +ELLIPSIS
        INFO: Records in route53:...
        '''
        (creates, updates) = self.metrics.get_metrics()
        records = self.get_records(record_type='CNAME', name=self.domain)
        return (creates, updates, len(records))

    def get_records(self, record_type=None, name=None, maxitems=None):
        ''' Get all records for given params.
        >>> records = dns.get_records() # doctest: +ELLIPSIS
        INFO: Records in route53:...
        >>> records[0] # doctest: +ELLIPSIS
        <Record:opsqa.ctgrd.com.:NS:ns-430.awsdns-53.com...
        >>> records = dns.get_records(
        ...     record_type='CNAME',
        ...     name='opsqa.ctgrd.com.') # doctest: +ELLIPSIS
        INFO: Records in route53:...
        >>> records['aws1devjmp1.opsqa.ctgrd.com.']
        {'resource': [u'ec2-50-16-187-199.compute-1.amazonaws.com'], \
'type': u'CNAME', \
'ttl': u'60'}
        '''
        if self.zone_id is None:
            print "Zone ID not set"
            return False
        srec = dict()
        records = self.conn.get_all_rrsets(self.zone_id, type=record_type,
                                           name=name, maxitems=maxitems)
        if record_type is not None:
            for rec in records:
                if rec.type == record_type:
                    srec[rec.name] = {'type': rec.type,
                                      'ttl': rec.ttl,
                                      'resource': rec.resource_records}
            print 'INFO: Records in route53: %s' % len(srec)
            return srec
        else:
            print 'INFO: Records in route53: %s' % len(records)
            return records

    def generate_records(self, nodes, record_type=None, ttl=60):
        ''' Check to see if record exists. Returns new and existing records.
        >>> nodes = {
        ...     'faketest1.opsqa.ctgrd.com': {
        ...         'resource': ['dummyhost1'],
        ...         'ttl': 60,
        ...         'type': 'CNAME'},
        ...     'faketest2.opsqa.ctgrd.com': {
        ...         'resource': ['dummyhost2'],
        ...         'ttl': 60,
        ...         'type': 'CNAME'}}
        >>> (erecords, nrecords, drecords) = dns.generate_records(
        ...  nodes, record_type='CNAME') # doctest: +ELLIPSIS
        INFO: Records in route53:...
        INFO: Record generation complete
        >>> erecords
        {}
        >>> nrecords
        {'faketest2.opsqa.ctgrd.com.': {'resource': ['dummyhost2'], \
'type': 'CNAME', \
'ttl': 60}, \
'faketest1.opsqa.ctgrd.com.': {'resource': ['dummyhost1'], \
'type': 'CNAME', \
'ttl': 60}}
        >>> type(drecords)
        <type 'dict'>
        '''
        exrecords = dict()
        new_records = dict()
        del_records = dict()
        records = self.get_records(name=self.domain, record_type=record_type)
        for name in nodes:
            name = self.get_fqdn(name) + "."
            if name in records:
                if record_type is not None:
                    if records[name]['type'] == record_type:
                        exrecords[name] = records[name]
                    else:
                        print ('WARN: Record %s found,'
                               'but type is not the same' % name)
                else:
                    exrecords[name] = records[name]
            else:
                new_records[name] = {
                    'type': record_type,
                    'ttl': ttl,
                    'resource': nodes[name.strip('.')]['resource']}
        ignore_records = 0
        unmanaged = ['rds.amazonaws.com', 'elb.amazonaws.com', 'amazonses.com']
        for name in records:
            if name not in exrecords:
                if (any(condition in records[name]['resource']
                        for condition in unmanaged)):
                    print 'INFO: Ignoring unmanaged record %s' % name
                    ignore_records += 1
                else:
                    del_records[name] = records[name]
        if ignore_records != 0:
            print 'INFO: Ignoring %s records, unmanaged' % ignore_records
        print 'INFO: Record generation complete'
        return (exrecords, new_records, del_records)

    def print_records(self, record_type=None, name=None,
                      maxitems=None, nms=True, soa=False):
        ''' Print Records found in Route53.
        >>> dns.print_records(record_type='NS', name='opsqa.ctgrd.com')
        INFO: Records in route53: 1
        Name             Type  TTL     Value
        opsqa.ctgrd.com. NS    172800  ns-430.awsdns-53.com.
        opsqa.ctgrd.com. NS    172800  ns-1157.awsdns-16.org.
        opsqa.ctgrd.com. NS    172800  ns-620.awsdns-13.net.
        opsqa.ctgrd.com. NS    172800  ns-1859.awsdns-40.co.uk.
        '''
        if self.zone_id is None:
            print "Zone ID not set"
            return False
        records = self.get_records(
            record_type=record_type, name=name, maxitems=maxitems)
        fmt = "%-16s %-5s %-7s %s"
        print fmt % ("Name", "Type", "TTL", "Value")
        if type(records) == dict:
            for name in records:
                if records[name]['type'] == "NS" and nms is False:
                    continue
                if records[name]['type'] == "SOA" and soa is False:
                    continue
                for rcr in records[name]['resource']:
                    print fmt % (self.get_uqdn(name), records[name]['type'],
                                 records[name]['ttl'], rcr)
        else:
            for rec in records:
                if rec.type == "NS" and nms is False:
                    continue
                if rec.type == "SOA" and soa is False:
                    continue
                for rcr in rec.resource_records:
                    print fmt % (self.get_uqdn(rec.name), rec.type,
                                 rec.ttl, rcr)

    def get_uqdn(self, name):
        ''' Returns the UQDN
        >>> dns.get_uqdn('aws1devjmp1.opsqa.ctgrd.com.')
        'aws1devjmp1'
        '''
        return self.re_uqdn.sub("", name)

    def get_tiny_dns_zone(self):
        ''' Export tiny dns zone.
        >>> zone = dns.get_tiny_dns_zone() # doctest: +ELLIPSIS
        INFO:...
        >>> zone # doctest: +ELLIPSIS
        u'&opsqa.ctgrd.com::ns-430.awsdns-53.com...
        '''
        zone = ""
        if self.zone_id is None:
            print "Zone ID not set"
            return False
        records = self.get_records(name=self.domain)
        for rec in records:
            for rcr in rec.resource_records:
                if rec.type == "NS":
                    zone += "&%s::%s\n" % (rec.name.rstrip("."), rcr)
                elif rec.type == "A":
                    zone += "+%s:%s\n" % (rec.name.rstrip("."), rcr)
                elif rec.type == "CNAME":
                    zone += "C%s:%s:%d\n" % (rec.name.rstrip("."),
                                             rcr, int(rec.ttl))
                elif rec.type == "SOA":
                    src = map(lambda x: x.rstrip("."), rcr.split(" "))
                    zone += "Z%s::%s:%s\n" % (rec.name.rstrip("."),
                                              src[0], src[1])
                else:
                    zone += "#%s %s:%s\n" % (rec.type,
                                             rec.name.rstrip("."), rcr)
        return zone
