#!/usr/bin/python2.7
''' Used to manage provision of EC2 servers and services. '''

import sys
import time
import optparse
import boto.sqs
import c3.utils.accounts
import c3.utils.naming
import c3.utils.tagger
import c3.utils.config
import c3.aws.ec2.elb
import c3.aws.ec2.ebs
import c3.aws.ec2.security_groups
from nvlib import Nventory
from zambi import ZambiConn
from c3.utils import logging
from boto.exception import SQSError
from boto.exception import EC2ResponseError
from c3.aws.ec2.instances import C3Instance


def parser_setup():
    ''' Setup the options parser. '''
    usage = 'usage: %prog [options]'
    desc = 'Provision instances and maintain SGs and ELBs'
    parser = optparse.OptionParser(usage=usage, description=desc)
    parser.add_option(
        '--config',
        '-c',
        action='store',
        type='string',
        dest='config_file',
        help='config (ini) file to use REQUIRED')
    parser.add_option(
        '--aws-account',
        '-A',
        action='store',
        type='string',
        dest='aws_account',
        help='AWS Account to use.')
    parser.add_option(
        '--instances',
        '-i',
        action='store',
        type='int',
        dest='count',
        help='number of instances to start')
    parser.add_option(
        '--verbose',
        '-v',
        action='store_true',
        default=False,
        dest='verbose',
        help='verbose output')
    parser.add_option(
        '--ami',
        '-a',
        action='store',
        type='string',
        dest='ami',
        help='AMI to use; should be a nv-configured name, '
        'but could be an actual AMI')
    parser.add_option(
        '--size',
        '-s',
        action='store',
        type='string',
        dest='size',
        help='instance size to use')
    parser.add_option(
        '--availability-zones',
        '-z',
        action='store',
        type='string',
        dest='azs',
        help='Availability Zone[s] (comma-separated) to use')
    parser.add_option(
        '--no-substitute-zones',
        '-Z',
        action='store_false',
        dest='substitute_zones',
        default=True,
        help='do not attempt another AZ on failure')
    parser.add_option(
        '--use-zones',
        '-u',
        action='store',
        type='int',
        dest='use_zones',
        default=None,
        help='maximum number of AZs to use')
    parser.add_option(
        '--allocate-eips',
        '-e',
        action='store_true',
        dest='allocate_eips',
        default=False,
        help='allocate and attach new EIPs for new instances')
    parser.add_option(
        '--nv-ini',
        '-n',
        action='store',
        type='string',
        dest='nv_ini',
        default="/app/secrets/nv_prd.ini",
        help='External DB ini file to use; useful for testing')
    parser.add_option(
        '--destroy',
        '-D',
        action='store',
        type='string',
        dest='destroy',
        default=None,
        help='set DESTROY to \'destroy\' to destroy the entire cluster, '
        'including ELB and SG')
    parser.add_option(
        '--hibernate',
        '-H',
        action='store_true',
        dest='hibernate',
        default=False,
        help='stop ALL instances in the cluster and exit')
    parser.add_option(
        '--wake',
        '-W',
        action='store_true',
        dest='wake',
        default=False,
        help='start ALL stopped instances in the cluster and exit')
    parser.add_option(
        '--status',
        '-S',
        action='store_true',
        dest='status',
        default=False,
        help='show the status of the cluster and exit')
    parser.add_option(
        '--retag',
        '-T',
        action='store_true',
        dest='retag',
        default=False,
        help='re-tag the cluster and exit')
    parser.add_option(
        '--skip-userdata',
        '-U',
        action='store_true',
        dest='skip_userdata',
        default=False,
        help='Skip Userdata script.')
    parser.add_option(
        '--ssh-key',
        '-k',
        action='store',
        type='string',
        dest='ssh_key',
        default=None,
        help='the ssh key ID used for starting instances')
    return parser


def check_timed_out(start_time, timeout, verbose=False):
    ''' Times out application if we are running to long. '''
    logging.debug(
        "check_timed_out(): Checking if %d - %d (%d) > %d" %
        (time.time(), start_time, time.time()-start_time, timeout), verbose)
    if time.time() - start_time > timeout:
        return True
    return False


def nv_connect(nv_ini):
    ''' Get a Nventory connection object. '''
    try:
        node_db = Nventory(ini_file=nv_ini)
        node_db.login()
    except Exception:
        raise
    return node_db


def cluster_tagger(conn, verbose=None):
    ''' Initialize the tagger. '''
    return c3.utils.tagger.Tagger(conn, verbose=verbose)


class C3EC2Provision(object):
    ''' This class manages provisioning in AWS. '''
    def __init__(self, opts):
        self.opts = opts
        self.cconfig = None
        self.conn = None
        self.hostnames = list()
        self.volume_instances = dict()
        self.volume_devices = dict()
        self.set_options()
        self.run_mode()

    def set_options(self):
        ''' Assign options and overrides for cluster configs. '''
        # Get the account name and pass to ClusterConfig
        if self.opts.aws_account:
            account_name = self.opts.aws_account
        else:
            account_name = c3.utils.config.get_account_from_conf(
                conf=self.opts.config_file)
        try:
            # Pass account name and load all the defaults
            self.cconfig = c3.utils.config.ClusterConfig(
                ini_file=self.opts.config_file,
                account_name=account_name,
                verbose=self.opts.verbose)
        except c3.utils.config.ConfigNotFoundException, msg:
            logging.error(msg)
            sys.exit(1)
        # this one MUST be "is not None", or a value of 0 won't work
        if self.opts.count is not None:
            logging.debug("setting count", self.opts.verbose)
            self.cconfig.set_count(self.opts.count)
        if self.opts.ami:
            logging.debug("setting AMI", self.opts.verbose)
            self.cconfig.set_ami(self.opts.ami)
        if self.opts.azs:
            logging.debug("setting AZs", self.opts.verbose)
            try:
                self.cconfig.set_azs(self.opts.azs)
            except c3.utils.config.InvalidAZError, msg:
                logging.error(msg)
                sys.exit(1)
        if self.opts.size:
            logging.debug("setting size", self.opts.verbose)
            self.cconfig.set_size(self.opts.size)
        if self.opts.use_zones:
            logging.debug("limiting AZs", self.opts.verbose)
            removed = self.cconfig.limit_azs(self.opts.use_zones)
            logging.debug("removed %d AZs" % removed, self.opts.verbose)
        if self.opts.ssh_key:
            logging.debug("setting ssh key", self.opts.verbose)
            self.cconfig.set_ssh_key(self.opts.ssh_key)
        if self.opts.allocate_eips:
            logging.debug("setting EIP allocation", self.opts.verbose)
            self.cconfig.set_allocate_eips()

    def run_mode(self):
        ''' Itterate through modes. '''
        if self.opts.destroy == "destroy":
            self.cluster_destroy()
        elif self.opts.destroy:
            logging.error(
                "Not a valid destory option: %s. Quitting." %
                self.opts.destroy)
            sys.exit(1)
        if self.opts.wake:
            self.cluster_wake()
        if self.opts.hibernate:
            self.cluster_hibernate()
        if self.opts.status:
            self.cluster_status()
        if self.opts.retag:
            self.cluster_retag()
        self.cluster_create()

    def aws_conn(self, service):
        ''' Gets a connection to EC2. '''
        zambi = ZambiConn()
        conn = zambi.get_connection(self.cconfig.get_aws_account(),
                                    service, self.cconfig.get_aws_region())
        return conn

    def cluster(self):
        ''' Gets an existing cluster object. '''
        node_db = nv_connect(self.opts.nv_ini)
        self.conn = self.aws_conn('ec2')
        try:
            cgc = c3.aws.ec2.instances.C3Cluster(
                self.conn, name=self.cconfig.get_primary_sg(),
                node_db=node_db, verbose=self.opts.verbose)
        except c3.aws.ec2.instances.C3ClusterNotFoundException, msg:
            logging.error("Problem finding cluster (%s)" % (msg))
            sys.exit(1)
        except c3.aws.ec2.instances.TooManySGsException, error:
            logging.error("Found multiple SGs! (%s)" % (error))
            sys.exit(1)
        except EC2ResponseError, msg:
            logging.error(msg.message)
            sys.exit(1)
        return cgc

    def elb_connection(self, find_only=True):
        ''' Get a connection to the ELB service. '''
        conn_elb = self.aws_conn('elb')
        try:
            c3elb = c3.aws.ec2.elb.C3ELB(
                conn_elb, self.cconfig.get_elb_name(),
                self.cconfig.get_elb_config(), find_only=find_only)
        except EC2ResponseError, msg:
            logging.error(msg.message)
        return c3elb

    def cluster_destroy(self):
        ''' Destroy mode, delete all components for this cluster. '''
        logging.info("Tearing down %s in %s" % (
            self.cconfig.get_primary_sg(), self.cconfig.get_aws_region()))
        cgc = self.cluster()
        count = cgc.destroy()
        logging.info('Terminated %d instance(s)' % count)
        if self.cconfig.elb.enabled:
            c3elb = self.elb_connection()
            if c3elb.destroy():
                logging.info('ELB %s deleted' % c3elb.name)
            else:
                logging.error('Deleting ELB %s failed')
        sgrp = c3.aws.ec2.security_groups.SecurityGroups(
            self.conn, self.cconfig.get_primary_sg(), find_only=True)
        if sgrp.destroy():
            logging.info("Security Group %s removed" % sgrp.name)
        logging.info('Tear down complete for %s' %
                     self.cconfig.get_primary_sg())
        sys.exit(0)

    def cluster_wake(self):
        ''' Wake a hibernating cluster. '''
        logging.info('Waking up %s' % self.cconfig.get_primary_sg())
        cgc = self.cluster()
        count = cgc.wake()
        logging.info("%d instance(s) in %s have been started" % (
            count, self.cconfig.get_primary_sg()))
        logging.info('Waking up instances complete')
        sys.exit(0)

    def cluster_hibernate(self):
        ''' Hibernates a running cluster. '''
        logging.info('Hibernating %s' % self.cconfig.get_primary_sg())
        cgc = self.cluster()
        count = cgc.hibernate()
        logging.info("%d instance(s) in %s have been hibernated" % (
            count, self.cconfig.get_primary_sg()))
        logging.info('Hibernating instances complete')
        sys.exit(0)

    def cluster_status(self):
        ''' Check the status of a cluster. '''
        logging.info('Checking status for %s' % self.cconfig.get_primary_sg())
        cgc = self.cluster()
        for instance in cgc.c3instances:
            elbm = None
            elb_hc = None
            elb_azs = None
            ebs_vols = None
            try:
                c3elb = self.elb_connection()
            except TypeError:
                c3elb = None
            if c3elb:
                if c3elb.instance_configured(instance.inst_id):
                    elbm = c3elb.get_dns()
                    elb_hc = c3elb.get_hc()
                    elb_azs = c3elb.get_azs()
            ebsm = instance.get_ebs_optimized()
            eipm = instance.get_associated_eip()
            vols = instance.get_non_root_volumes()
            if vols:
                ebs_vols = list()
                for key, value in vols.items():
                    ebs_vols.append('%s: %s' % (str(key), str(value)))
            msg = '''
            Instance %s
                ID: %s
                State: %s
                EBS Optimized: %s
                EBS Volumes: %s
                EIP: %s
                ELB %s
                    Health Check: %s
                    Availability Zones: %s
            ''' % (instance.name, instance.inst_id, instance.state,
                   ebsm, ebs_vols, eipm, elbm, elb_hc, elb_azs)
            logging.info(msg)
        logging.info('Status complete')
        sys.exit(0)

    def cluster_retag(self):
        ''' Retag the cluster. '''
        logging.info('Retagging cluster %s' % self.cconfig.get_primary_sg())
        cgc = self.cluster()
        tagger = cluster_tagger(self.conn, verbose=self.opts.verbose)
        if not tagger.add_tags(
                cgc.get_instance_ids(), self.cconfig.get_tagset()):
            logging.error('Problem addings tags')
            sys.exit(1)
        logging.info('Retag cluster complete')
        sys.exit(0)

    def check_config_types(self):
        ''' Check if there is an assigned ssh key. '''
        if self.cconfig.get_count() and not self.cconfig.get_ssh_key():
            logging.error(
                "You're trying to start instances, "
                "but don't have an SSH key set")
            sys.exit(1)
        node_db = nv_connect(self.opts.nv_ini)
        if not self.cconfig.get_resolved_ami(node_db):
            logging.error('Getting AMI failed, exiting')
            sys.exit(1)

    def sg_rules(self):
        ''' Find/create SG rules. '''
        primary_sg = c3.aws.ec2.security_groups.SecurityGroups(
            self.conn, self.cconfig.get_primary_sg())
        # add CIDR rules
        for rule in self.cconfig.get_cidr_rules():
            primary_sg.add_ingress(
                [rule['fport'], rule['lport']], rule['proto'],
                rule['cidr'])
        # add SG-to-SG rules
        for rule in self.cconfig.get_sg_rules():
            primary_sg.add_ingress(
                [rule['fport'], rule['lport']], rule['proto'],
                None, rule['owner'], rule['sg'])

    def userdata_replacements(self, host):
        ''' Replace properties to be passed to userdata. '''
        use_raid = self.cconfig.raid.enabled
        logging.debug("Determine if we need RAID", self.opts.verbose)
        if use_raid:
            raid_level = self.cconfig.raid.level
            logging.debug("Setting RAID level", self.opts.verbose)
            raid_device = self.cconfig.raid.device
            logging.debug("Setting RAID device", self.opts.verbose)
        else:
            raid_level = 0
            raid_device = "None"
            logging.debug('No RAID to configure', self.opts.verbose)
        fs_type = self.cconfig.get_fs_type()
        logging.debug('Setting fs_type: %s' % fs_type, self.opts.verbose)
        replacements = {
            '__HOSTNAME__': '"%s"' % host,
            '__DEVICES__': '%s' % len(self.cconfig.get_ebs_config()),
            '__USE_RAID__': '%s' % use_raid,
            '__RAID_LEVEL__': '%s' % raid_level,
            '__RAID_DEVICE__': '%s' % raid_device,
            '__FS_TYPE__': '%s' % fs_type,
            '__SKIP_USERDATA__': '%s' % self.opts.skip_userdata}
        logging.debug('Setting user Data Replacements: %s' %
                      replacements, self.opts.verbose)
        return replacements

    def cluster_create(self):
        ''' Provisions a new cluster based on a config. '''
        self.conn = self.aws_conn('ec2')
        node_db = nv_connect(self.opts.nv_ini)
        success = 0
        failed = 0
        self.check_config_types()
        logging.info('Applying SG Rules to %s' % self.cconfig.get_primary_sg())
        self.sg_rules()
        if self.cconfig.get_count():
            servers = dict()
            logging.debug(
                'Creating %d %s in %s using %s.' % (
                    self.cconfig.get_count(), self.cconfig.get_size(),
                    self.cconfig.get_azs(), self.cconfig.get_ami()),
                self.opts.verbose)
            self.hostnames = c3.utils.naming.find_available_hostnames(
                self.cconfig.get_primary_sg(), self.cconfig.get_count(),
                self.cconfig.get_aws_account(),
                self.cconfig.get_aws_region(), 'ctgrd.com', node_db)
            start_time = time.time()
            logging.debug(
                'Creating new servers: %s' % self.hostnames,
                self.opts.verbose)
            for host in self.hostnames:
                servers[host] = C3Instance(
                    conn=self.conn, node_db=node_db,
                    verbose=self.opts.verbose)
                userdata = self.cconfig.get_user_data(
                    self.userdata_replacements(host))
                tries = 1
                if self.opts.substitute_zones:
                    tries = len(self.cconfig.get_azs())
                while tries > 0:
                    tries -= 1
                    used_az = self.cconfig.get_next_az()
                    logging.info("Starting %s in %s" % (host, used_az))
                    instance = servers[host].start(
                        self.cconfig.get_ami(), self.cconfig.get_ssh_key(),
                        self.cconfig.get_sgs(), userdata,
                        host, self.cconfig.get_size(), used_az,
                        self.cconfig.get_node_groups(),
                        self.cconfig.get_allocate_eips(),
                        self.cconfig.get_use_ebs_optimized())
                    if instance:
                        success += 1
                        break
                    else:
                        if tries:
                            logging.warn(
                                'Failed to create %s in %s, retrying' %
                                (host, used_az))
                else:
                    logging.error(
                        "Failed to create %s in all AZs, trying next instance" %
                        host)
                    failed += 1
                if len(self.cconfig.get_ebs_config()) > 0:
                    self.create_ebs(used_az, host, servers[host].get_id())
            if failed == self.cconfig.get_count():
                logging.error(
                    '%d of %d failed to create, dying' %
                    (failed, self.cconfig.get_count()))
                sys.exit(1)
            logging.info(
                '%d of %d server(s) created' %
                (success, self.cconfig.get_count()))
            self.wait_for_servers(servers, start_time, success)
            if self.volume_instances:
                self.attach_ebs()
            self.tag_by_instance(servers)
            if self.cconfig.get_server_env() == 'prd':
                self.puppet_whitelist()
        logging.info('Cluster config complete')

    def create_ebs(self, used_az, host, instance_id):
        ''' Create new EBS volumes. '''
        cgebs = c3.aws.ec2.ebs.C3EBS(self.conn)
        for ebsv in self.cconfig.get_ebs_config():
            logging.info(
                "Creating EBS volume %s for %s" %
                (ebsv['device'], host))
            volume = cgebs.create_volume(
                ebsv['size'], used_az,
                ebsv['type'], ebsv['iops'])
            #pylint: disable=maybe-no-member
            self.volume_instances[volume.id] = instance_id
            self.volume_devices[volume.id] = ebsv['device']

    def wait_for_servers(self, servers, start_time, success):
        ''' Wait for servers that didn't fail to start to start up. '''
        started = 0
        failed = 0
        azs_used = list()
        logging.info('Waiting for %d server(s)to start' % success)
        stime = self.cconfig.get_sleep_step()
        for host in self.hostnames:
            status = servers[host].analyze_state()
            while status == 1:
                if check_timed_out(start_time,
                                   self.cconfig.get_launch_timeout(),
                                   verbose=self.opts.verbose):
                    logging.error(
                        '%s failed to start before time out' % host)
                    break
                logging.info('Wating for %s to enter running state' % host)
                time.sleep(stime)
                status = servers[host].analyze_state()
            if status == 0:
                started += 1
                if servers[host].get_az() not in azs_used:
                    azs_used.append(servers[host].get_az())
                logging.info('%s is running' % host)
            elif status == 2:
                failed += 1
        logging.debug(
            "%d started, %d failed, of %d total" %
            (started, failed, success), self.opts.verbose)
        if failed == success:
            logging.error(
                'All %d server(s) failed to start' % failed)
            sys.exit(1)
        elif started != success:
            logging.error(
                '%d started, %d failed to start' % (started, failed))
        else:
            logging.info(
                '%d of %d started' % (started, success))
        if self.cconfig.elb.enabled and azs_used:
            self.setup_elb(servers, azs_used)

    def setup_elb(self, servers, azs_used):
        ''' Createst the cluster ELB. '''
        self.cconfig.elb.set_azs(azs_used)
        c3elb = self.elb_connection(find_only=False)
        for host in self.hostnames:
            try:
                instance_id = servers[host].get_id()
            except AttributeError, msg:
                logging.error(msg)
                instance_id = None
            if instance_id:
                c3elb.add_instances([instance_id])

    def attach_ebs(self):
        ''' Attaches EBS volumes to instances. '''
        cgebs = c3.aws.ec2.ebs.C3EBS(self.conn)
        for vol_id in self.volume_instances:
            logging.info("Attaching EBS volume %s on %s to %s" % (
                vol_id, self.volume_instances[vol_id],
                self.volume_devices[vol_id]))
            cgebs.attach_volume(
                vol_id, self.volume_instances[vol_id],
                self.volume_devices[vol_id])
            cgebs.set_ebs_del_on_term(
                self.volume_instances[vol_id], self.volume_devices[vol_id])

    def tag_by_instance(self, servers):
        ''' Tag resources tied to an instnace ID. '''
        tagger = cluster_tagger(self.conn, verbose=self.opts.verbose)
        for host in self.hostnames:
            try:
                instance_id = servers[host].get_id()
                if not tagger.add_tags(
                        [instance_id], self.cconfig.get_tagset()):
                    logging.error("Problem adding %s to %s" % (
                        self.cconfig.get_tagset(), instance_id))
            except AttributeError:
                instance_id = None
                logging.warn(
                    'Failed to set cost tags on failed '
                    'instance %s' % host)

    def puppet_whitelist(self):
        ''' Add the puppet whitelists. '''
        conn_sqs = self.aws_conn('sqs')
        qurl = self.cconfig.get_whitelist_url()
        try:
            sqsq = boto.sqs.queue.Queue(conn_sqs, url=qurl)
        except SQSError, msg:
            logging.error(msg.message)
            sys.exit(1)
        for host in self.hostnames:
            try:
                #pylint: disable=maybe-no-member
                conn_sqs.send_message(sqsq, host)
            except SQSError, msg:
                logging.error(msg.message)


def main():
    ''' Read in command line options and manage instance provisioning. '''
    parser = parser_setup()
    (opts, args) = parser.parse_args()
    if args:
        parser.print_help()
        parser.error('Too many arguments')
    if opts.config_file is None:
        parser.print_help()
        parser.error('"-c CONFIG_FILE" is required')
    C3EC2Provision(opts)


if __name__ == '__main__':
    main()
