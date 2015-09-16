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
''' Organize options from config files '''
import os
import re
import sys
import ConfigParser
import c3.aws.ec2.ebs
import c3.utils.naming
import c3.utils.accounts
from c3.utils import logging
from ConfigParser import SafeConfigParser


def get_account_from_conf(conf=None):
    ''' Loads config only so we can get the account for ClusterConfig. '''
    scp = SafeConfigParser()
    scp.read(conf)
    try:
        return scp.get('cluster', 'aws_account')
    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError), msg:
        logging.error(msg)
        return None


def get_hvm_instances():
    ''' HVM instance types that are not compatible with paravirtual AMIs '''
    instances = [
        'cc2.8xlarge',
        'i2.xlarge',
        'i2.2xlarge',
        'i2.4xlarge',
        'i2.8xlarge',
        'r3.large',
        'r3.xlarge',
        'r3.2xlarge',
        'r3.4xlarge',
        'r3.8xlarge',
        't2.micro',
        't2.small',
        't2.medium',
    ]
    return instances


def verify_az(avz):
    ''' Verify AZ via regex '''
    if re.match(r"^\w+-\w+-\d\w$", avz):
        return True
    return False


class TooManyAMIsError(Exception):
    ''' Returns too many AMI exception '''
    def __init__(self, value):
        super(TooManyAMIsError, self).__init__(value)
        self.value = value

    def __str__(self):
        return self.value


class AMINotFoundError(Exception):
    ''' Return AMI not found exception '''
    def __init__(self, value):
        super(AMINotFoundError, self).__init__(value)
        self.value = value

    def __str__(self):
        return self.value


class InvalidAZError(Exception):
    ''' Returns invalid AZ exception'''
    def __init__(self, value):
        super(InvalidAZError, self).__init__(value)
        self.value = value

    def __str__(self):
        return self.value


class InvalidCIDRNameError(Exception):
    ''' Return invalid cidr name exception '''
    def __init__(self, value):
        super(InvalidCIDRNameError, self).__init__(value)
        self.value = value

    def __str__(self):
        return self.value


class ConfigNotFoundException(Exception):
    ''' Return config not found exception '''
    def __init__(self, value):
        super(ConfigNotFoundException, self).__init__(value)
        self.value = value

    def __str__(self):
        return self.value

class EBSConfig(object):
    ''' A class to hold EBS configuration data '''
    def __init__(self):
        self.volumes = list()
        self.azs = list()

    def add_volumes(self, vol_type, device, size, iops):
        ''' Add volume information '''
        self.volumes.append(
            {'type': vol_type, 'device': device, 'size': size, 'iops': iops})

    def get_volumes(self):
        ''' Return volume information '''
        return self.volumes

    def set_azs(self, azs):
        ''' Set AZ for volume '''
        self.azs = azs

    def get_azs(self):
        ''' Get AZ information for volume '''
        return self.azs


class ELBConfig(object):
    ''' A simple class to hold ELB configuration data '''
    # pylint: disable=too-many-instance-attributes
    # Appropriate number of attributes for an ELB
    def __init__(self):
        self.enabled = None
        self.protocol = None
        self.public_port = None
        self.private_port = None
        self.vip_number = None
        self.hc_access_point = None
        self.hc_interval = None
        self.hc_target = None
        self.hc_healthy_threshold = None
        self.hc_unhealthy_threshold = None
        self.azs = list()

    def validate(self):
        ''' Validate required config options are set'''
        if not self.enabled:
            return self.enabled
        items = [
            'protocol', 'public_port', 'private_port',
            'hc_access_point', 'hc_interval', 'hc_target',
            'hc_healthy_threshold', 'hc_unhealthy_threshold', 'vip_number']
        for item in items:
            if getattr(self, item) is None:
                msg = '%s not set, disabling ELB' % item
                logging.error(msg)
                self.enabled = False
        return self.enabled

    def set_azs(self, azs):
        ''' Set ELB AZ '''
        self.azs = azs

    def get_azs(self):
        ''' Set ELB AZ '''
        return self.azs


class SGConfig(object):
    ''' A class to store SG config objects '''
    def __init__(self):
        self.cidr_rules = list()
        self.sg_rules = list()

    def add_cidr(self, proto, fport, lport, cidr):
        ''' Add cidr rules '''
        self.cidr_rules.append(
            {'proto': proto, 'fport': fport, 'lport': lport, 'cidr': cidr})

    def add_sg(self, proto, fport, lport, owner, sgrp):
        ''' Add SG rules '''
        # pylint: disable=too-many-arguments
        # Appropriate number arguments of for add_sg
        self.sg_rules.append(
            {'proto': proto, 'fport': fport,
             'lport': lport, 'owner': owner, 'sg': sgrp})

    def get_cidr(self):
        ''' Get cidr rules '''
        return self.cidr_rules

    def get_sg(self):
        ''' Get sg rules '''
        return self.sg_rules


class RAIDConfig(object):
    ''' A simple class to hold RAID configuration data '''
    def __init__(self):
        self.enabled = None
        self.level = None
        self.device = None

    def set_level(self, level):
        ''' Set the RAID level '''
        self.level = level

    def set_device(self, device):
        ''' Set the RAID device '''
        self.device = device

    def get_level(self):
        ''' Returns RAID level '''
        return self.level

    def get_device(self):
        ''' Returns RAID device '''
        return self.device


class RDSSGConfig(object):
    ''' This Class is used to build RDS SG Authorizations. '''
    def __init__(self):
        self.cidr_rules = list()
        self.sg_rules = list()

    def add_cidr(self, cidr):
        ''' Add CIDR rules to cidr list. '''
        self.cidr_rules.append({'cidr': cidr})

    def add_sg(self, oid, sid):
        ''' Add SG rules to cidr list. '''
        self.sg_rules.append({'oid': oid, 'sid': sid})

    def get_cidr(self):
        ''' Returns populated list of CIDR rules. '''
        return self.cidr_rules

    def get_sg(self):
        ''' Returns populated list of SG rules. '''
        return self.sg_rules


class RDSPGConfig(object):
    ''' This Class is used to get RDS Parameters. '''
    def __init__(self):
        self.rds_parameters = list()

    def add_parameter(self, parameter):
        ''' Add RDS Parameter to list. '''
        self.rds_parameters.append(parameter)

    def get_parameters(self):
        ''' Returns list of paramters. '''
        return self.rds_parameters


class RDSInstanceConfig(object):
    ''' Manages storeing RDS config items. '''
    def __init__(self):
        self.rds_conf = dict()

    def add_config(self, key, value):
        ''' Used to Store RD config items into a dictionary. '''
        self.rds_conf[key] = value

    def get_config(self):
        ''' Returns RDS config dictionary. '''
        return self.rds_conf


class ClusterConfig(object):
    """ A class to hold and manage cluster configuration data
    Config will come from all of the following, in priority order:
    1) The command line, via the Set methods
    2) The Class config file, named $env$class.ini
    3) The $AWS_CONF_DIR/cluster_defaults.ini.$AWS_PROFILE_NAME
    4) The $AWS_CONF_DIR/cluster_defaults.ini
    5) The $HOME/.cluster_defaults.ini (for "sshkey" only)
    """
    # pylint: disable=too-many-instance-attributes
    # Appropriate number of attributes for ClusterConfig
    def __init__(self, ini_file=None, account_name=None, prv_type='ec2',
                 verbose=False, no_defaults=False):
        self.no_defaults = no_defaults  # only read self.classfile if True
        self.defaults = os.getenv('AWS_CONF_DIR') + '/cluster_defaults.ini'
        # This should hold only the ssh key
        self.personal_defaults = os.getenv('HOME') + '/.cluster_defaults.ini'
        self.classfile = ini_file
        if not os.path.exists(ini_file):
            raise ConfigNotFoundException('Invalid config: %s' % ini_file)
        self.verbose = verbose
        self.account_name = account_name
        self.global_ssg = None
        self.primary_sg = None
        # These aren't IN the config file, they're implied by the name
        self.server_env = None
        self.server_class = None
        # This should be looked up from the AZs used
        self.server_datacenter = None
        self.user_data_raw = None
        self.domain = None
        self.ebs = EBSConfig()
        self.elb = ELBConfig()
        self.sgrp = SGConfig()
        self.raid = RAIDConfig()
        self.rds = RDSInstanceConfig()
        self.rds_sg = RDSSGConfig()
        self.rds_pg = RDSPGConfig()
        self.tagset = dict()
        self.overrides = dict()
        self.ini_files = list()
        self.ini = None
        # Read the in the INI files
        if self.no_defaults:
            self.read_files([self.classfile])
        else:
            self.read_files(
                [self.personal_defaults, self.defaults,
                 "%s-%s" % (self.defaults, self.account_name), self.classfile])
        self.get_meta_data()
        self.server_datacenter = self.get_cg_region()
        self.read_sections(prv_type)

    def read_sections(self, prv_type):
        ''' Read sections based on provisioning type '''
        if prv_type == 'ec2':
            if self.ini.has_section('ebs'):
                self.read_ebs_config()
            if self.ini.has_section('elb'):
                self.read_elb_config()
            if self.ini.has_section('securitygroup'):
                self.read_sg_config()
            if self.ini.has_section('raid'):
                self.read_raid_config()
        elif prv_type == 'rds':
            if self.ini.has_section('rds_provision'):
                self.read_rds_config()
            if self.ini.has_section('rds_securitygroup'):
                self.read_rds_sg_config()
            if self.ini.has_section('rds_parameters'):
                self.read_rds_pg_config()

    def get_meta_data(self):
        ''' Get metadata from classfile '''
        self.server_env = os.path.basename(self.classfile)[:3]
        self.server_class = os.path.basename(self.classfile)[3:6]
        self.primary_sg = '%s%s' % (self.server_env, self.server_class)
        self.global_ssg = 'ssg-management'

    def get_server_env(self):
        ''' Return the server Environment '''
        return self.server_env

    def get_primary_sg(self):
        ''' Return the primary SG '''
        return self.primary_sg

    def get_global_ssg(self):
        ''' Return the Global SG '''
        return self.global_ssg

    def get_aws_region(self):
        ''' We work in only one region, so we can just take the first '''
        if self.get_azs()[0] == 'auto':
            return 'us-east-1'
        else:
            return self.get_azs()[0][:-1]

    def get_cg_region(self):
        ''' Return region from c3.utils.naming.get_aws_dc '''
        return c3.utils.naming.get_aws_dc(self.get_aws_region())

    def read_files(self, conf_files):
        ''' Read in ini files '''
        logging.debug('Trying %s' % conf_files, self.verbose)
        for ini in conf_files:
            if os.path.exists(ini):
                self.ini_files.append(ini)
        logging.debug('Reading %s' % self.ini_files, self.verbose)
        self.ini = ConfigParser.ConfigParser({
            'AWS_BASE_DIR': os.getenv('AWS_BASE_DIR'),
            'AWS_CONF_DIR': os.getenv('AWS_CONF_DIR')})
        self.ini.read(self.ini_files)

    def get_ini(self, section, name, castf, fallback=None):
        ''' Get a setting from the ini files '''
        try:
            return castf(self.ini.get(section, name))
        except ConfigParser.NoSectionError, msg:
            logging.error(msg)
            return fallback
        except ConfigParser.NoOptionError, msg:
            logging.error(msg)
            return fallback
        return fallback

    def set_ami(self, ami):
        ''' Set AMI '''
        self.overrides['ami'] = ami

    def get_ami(self):
        ''' Return the AMI '''
        if 'ami' in self.overrides:
            return self.overrides['ami']
        instance_type = self.get_size()
        raw_ami = self.get_ini('cluster', 'ami', str)
        if raw_ami.count('VTYPE'):
            if instance_type in get_hvm_instances():
                return raw_ami.replace('VTYPE', 'hvm')
            else:
                return raw_ami.replace('VTYPE', 'paravirtual')
        else:
            return raw_ami

    def get_whitelist_url(self):
        ''' Return the whitelist URL for puppet whitelisting '''
        if 'whitelisturl' in self.overrides:
            return self.overrides['whitelisturl']
        return self.get_ini("cluster", "whitelisturl", str)

    def get_resolved_ami(self, node_db):
        ''' Return resolved AMI '''
        ami = self.get_ami()
        if ami[:4] == 'ami-':
            logging.error(
                'AMI statically set to %s. Please use graffiti values' % ami)
            return ami
        try:
            amis = node_db.get_amis(self.get_cg_region(), ami)
        except:
            raise AMINotFoundError("No AMI matching '%s' found" % ami)
        if amis is None:
            raise AMINotFoundError("No AMI matching '%s' found" % ami)
        if len(amis) == 1:
            newami = amis.values()[0]
            self.set_ami(newami)
            logging.debug(
                "Converted '%s' to '%s'" % (ami, newami), self.verbose)
            return newami
        elif len(amis) > 1:
            raise TooManyAMIsError("%s matches too many AMIs: %s" % (ami, amis))

    def limit_azs(self, limit):
        ''' Limit the number of AZs to use '''
        if limit > 0:
            oldazs = self.get_azs()
            newazs = oldazs[:limit]
            self.set_azs(','.join(newazs))
            return len(oldazs) - len(newazs)
        else:
            logging.error("Trying to limit AZs to %d" % limit)
        return 0

    def set_azs(self, azs):
        ''' Set comma sperated list of AZs '''
        for avz in azs.split(","):
            if not verify_az(avz):
                raise InvalidAZError("AZ '%s' is invalid" % avz)
        self.overrides['azs'] = azs.split(",")

    def get_azs(self):
        ''' Return AZ information '''
        zones = list()
        if 'azs' in self.overrides:
            return self.overrides['azs']
        ret = self.get_ini("cluster", "zone", str)
        if ret:
            for avz in ret.split(","):
                if not verify_az(avz):
                    raise InvalidAZError("AZ '%s' is invalid" % avz)
                zones.append(avz.strip())
        return zones

    def get_next_az(self):
        ''' We'll need them in a list to do this, stick in overrides '''
        if 'azs' not in self.overrides:
            self.overrides['azs'] = self.get_azs()
        avz = self.overrides['azs'].pop(0)
        self.overrides['azs'].append(avz)
        return avz

    def get_count_azs(self):
        ''' Get the count of unique AZs '''
        return len(set(self.get_azs()))

    def set_count(self, count):
        ''' Set the instance count '''
        self.overrides['count'] = int(count)

    def get_count(self):
        ''' Return the instance count '''
        if 'count' in self.overrides:
            return self.overrides['count']
        return self.get_ini("cluster", "instance_count", int)

    def set_size(self, size):
        ''' Set the instance size '''
        self.overrides['size'] = size

    def get_size(self):
        ''' Return the instance size '''
        if 'size' in self.overrides:
            return self.overrides['size']
        return self.get_ini("cluster", "instance_size", str)

    def set_ssh_key(self, sshkey):
        ''' Set the ssh key '''
        self.overrides['sshkey'] = sshkey

    def get_ssh_key(self):
        ''' Return the ssh key '''
        if 'sshkey' in self.overrides:
            return self.overrides['sshkey']
        return self.get_ini("ssh", "sshkey", str)

    def get_dc(self):
        ''' Get the AWS region '''
        if self.get_ini("DEFAULT", "datacenter", str) is not None:
            logging.error(
                "The 'datacenter' option is no longer read from the INI file")
        return self.get_cg_region()

    def get_user_data_file(self):
        ''' Return the userdata file '''
        return self.get_ini("cluster", "user_data_file", str, None)

    def get_user_data(self, replacements=None):
        ''' Get userdata and set replacements '''
        path = self.get_user_data_file()
        logging.debug('user_data_file: %s' % path, self.verbose)
        if not self.user_data_raw:
            if os.path.exists(path):
                try:
                    udfile = file(path, "r")
                except IOError, msg:
                    logging.error(msg)
                    return None
                self.user_data_raw = udfile.read()
                udfile.close()
        udata = self.user_data_raw
        if replacements:
            for key in replacements.keys():
                logging.debug(
                    'Replacing %s with %s in %s' %
                    (key, replacements[key], path), self.verbose)
                udata = udata.replace(key, replacements[key])
        return udata.strip()

    def get_tagset(self):
        ''' Return the tagset cost tags '''
        self.tagset['BusinessUnit'] = self.get_ini("tags", "business_unit", str)
        self.tagset['Team'] = self.get_ini("tags", "team", str)
        self.tagset['Project'] = self.get_ini("tags", "project", str)
        if any(ent for ent in self.ini_files if ent.endswith('meta.ini')):
            self.tagset['Component'] = self.get_ini("tags", "component", str)
            self.tagset['Env'] = self.get_ini("tags", "env", str)
        else:
            comp = self.get_ini("tags", "component", str)
            if comp[:4] == self.server_class + ' ':
                self.tagset['Component'] = self.get_ini(
                    "tags", "component", str)
            else:
                self.tagset['Component'] = "%s %s" % (
                    self.server_class, self.get_ini("tags", "component", str))
            self.tagset['Env'] = self.get_server_env()
        return self.tagset

    def get_launch_timeout(self):
        ''' Return launch timeout '''
        return self.get_ini("cluster", "launch_timeout", int)

    def get_sleep_step(self):
        ''' R eturn sleep step '''
        return self.get_ini("cluster", "sleep_step", int)

    def add_sg(self, sgp):
        ''' Adding additional SGs '''
        if 'other_sgs' not in self.overrides:
            self.overrides['other_sgs'] = self.get_additional_sgs()
        self.overrides['other_sgs'].append(sgp)

    def get_additional_sgs(self):
        ''' Returns additonal SGs'''
        other_sgs = list()
        if 'other_sgs' in self.overrides:
            return self.overrides['other_sgs']
        ret = self.get_ini("cluster", "additional_sgs", str)
        if ret:
            for sgr in ret.split(','):
                other_sgs.append(sgr.strip())
        return other_sgs

    def get_sgs(self):
        ''' Return all SGs '''
        ret = self.get_additional_sgs()
        ret.append("%s%s" % (self.server_env, self.server_class))
        return ret

    def get_node_groups(self):
        ''' Return Node groups '''
        node_groups = list()
        if 'node_groups' in self.overrides:
            return self.overrides['node_groups']
        ret = self.get_ini("cluster", "node_groups", str)
        if ret:
            for ngrp in ret.split(','):
                node_groups.append(ngrp.strip())
        return node_groups

    def set_allocate_eips(self):
        ''' Set allocated EIPs '''
        self.overrides['allocate_eips'] = True
        return True

    def get_allocate_eips(self):
        ''' Return allocated EIPs '''
        if 'allocate_eips' in self.overrides:
            return self.overrides['allocate_eips']
        if self.get_ini("cluster", "allocate_eip", str) == "True":
            allocate_eips = True
        else:
            allocate_eips = False
        return allocate_eips

    def set_use_ebs_optimized(self):
        ''' Set use EBS optimized '''
        self.overrides['use_ebs_optimized'] = True

    def get_use_ebs_optimized(self):
        ''' Get EBS optimized option '''
        if 'use_ebs_optimized' in self.overrides:
            return self.overrides['use_ebs_optimized']
        if self.get_ini("cluster", "use_ebs_optimized", str):
            use_ebs_optimized = True
        else:
            use_ebs_optimized = False
        return use_ebs_optimized

    def get_aws_account(self):
        ''' Returns AWS account name. '''
        return self.account_name

    def get_domain(self):
        ''' Returns domain '''
        return self.get_ini('cluster', 'domain', str)

    def get_fs_type(self):
        ''' Get the filesystem type '''
        return self.get_ini('cluster', 'fs_type', str)

    def read_ebs_config(self):
        ''' Read EBS config options '''
        for vol in self.ini.items("ebs"):
            if len(vol[1].split()) == 3:
                device = vol[0]
                (vol_type, size, iops) = vol[1].split(" ")
                self.ebs.add_volumes(
                    vol_type, "/dev/" + device, size, iops)
            elif len(vol[1].split()) == 2:
                device = vol[0]
                (vol_type, size) = vol[1].split(" ")
                self.ebs.add_volumes(
                    vol_type, "/dev/" + device, size, None)

    def get_ebs_config(self):
        ''' Return EBS config options '''
        return self.ebs.get_volumes()

    def read_elb_config(self):
        ''' Read in ELB config options '''
        if self.get_ini("elb", "enabled", str) == "True":
            self.elb.enabled = True
        else:
            self.elb.enabled = False
            return False
        self.elb.protocol = self.get_ini("elb", "protocol", str)
        self.elb.public_port = self.get_ini("elb", "public_port", int)
        self.elb.private_port = self.get_ini("elb", "private_port", int)
        self.elb.vip_number = self.get_ini("elb", "vip_number", int) or 1
        self.elb.hc_access_point = self.get_ini(
            "healthcheck", "hc_access_point", str)
        self.elb.hc_interval = self.get_ini("healthcheck", "hc_interval", int)
        self.elb.hc_target = self.get_ini("healthcheck", "hc_target", str)
        self.elb.hc_healthy_threshold = self.get_ini(
            "healthcheck", "hc_healthy_threshold", int)
        self.elb.hc_unhealthy_threshold = self.get_ini(
            "healthcheck", "hc_unhealthy_threshold", int)
        self.elb.validate()

    def get_elb_config(self):
        ''' Return ELB config '''
        return self.elb

    def get_elb_name(self):
        ''' Return the name of the ELB, based on cluster and ELB configs '''
        return "%s%svip%s%d" % (
            self.get_cg_region(), self.server_env[:1],
            self.server_class, self.elb.vip_number)

    def read_sg_config(self):
        ''' Reads in SG config options '''
        for item in self.ini.items("securitygroup"):
            if item[1][:7] == "ingress":
                (rtype, proto, ports, remote) = item[1].split(" ")
                if ports == "None":
                    (prt1, prt2) = [-1, -1]
                elif '-' in ports:
                    (prt1, prt2) = ports.split("-")
                else:
                    prt1 = prt2 = ports
                prt1 = int(prt1)
                prt2 = int(prt2)
                if remote[:5] == 'CIDR:':
                    self.sgrp.add_cidr(proto, prt1, prt2, remote[5:])
                elif remote[:4] == 'Net:':
                    cidr = c3.utils.naming.get_cidr(remote[4:])
                    if not cidr:
                        raise InvalidCIDRNameError(
                            "Network '%s' is invalid" % remote[4:])
                    self.sgrp.add_cidr(proto, prt1, prt2, cidr)
                elif remote[:3] == 'SG:':
                    acct, sgrp = remote[3:].split("/")
                    if acct == 'self':
                        acctid = c3.utils.accounts.get_account_id(
                            account_name=self.get_aws_account())
                    elif acct == 'amazon-elb':
                        logging.debug('acctid set to amazon-elb', self.verbose)
                        acctid = 'amazon-elb'
                    else:
                        acctid = c3.utils.accounts.get_account_id(
                            account_name=acct)
                        logging.debug('%s == %s' % (acct, acctid), self.verbose)
                    if acctid:
                        self.sgrp.add_sg(proto, prt1, prt2, acctid, sgrp)
                    else:
                        logging.error("Can't find my own account.")
                logging.debug(
                    "Allowing %s %s for ports %d to %d from %s" %
                    (rtype, proto, prt1, prt2, remote), self.verbose)

    def get_sg_rules(self):
        ''' Return SG rules '''
        return self.sgrp.get_sg()

    def get_cidr_rules(self):
        ''' Return CIDR rules '''
        return self.sgrp.get_cidr()

    def read_raid_config(self):
        ''' Read in RAID config options '''
        if self.get_ini("raid", "enabled", str) == 'True':
            self.raid.enabled = True
        else:
            self.raid.enabled = False
            return False
        self.raid.set_level(self.get_ini("raid", "level", str))
        self.raid.set_device(self.get_ini("raid", "device", str))

    def read_rds_sg_config(self):
        ''' Reads RDS SG authorizations from ini files. '''
        for rule in self.ini.items('rds_securitygroup'):
            if re.match('.*rule', rule[0]):
                (rtype, rvalue) = rule[1].split(':')
                if rtype == 'Net':
                    cidr = c3.utils.naming.get_cidr(rvalue)
                    if cidr:
                        logging.debug('Appending RDS CIDR rule %s' % cidr,
                                    self.verbose)
                        self.rds_sg.add_cidr(cidr)
                elif rtype == 'CIDR':
                    logging.debug('Appending RDS CIDR rule %s' % rvalue,
                                self.verbose)
                    self.rds_sg.add_cidr(rvalue)
                elif rtype == 'SG':
                    (oid, sid) = rvalue.split('/')
                    if oid != 'self':
                        acctid = c3.utils.accounts.get_account_id(oid)
                    else:
                        acctid = c3.utils.accounts.get_account_id(
                            self.get_aws_account())
                    if acctid:
                        logging.debug(
                            'Appending RDS SG rule %s:%s' % (acctid, sid),
                            self.verbose)
                        self.rds_sg.add_sg(acctid, sid)
                    else:
                        logging.warn("Can't find account for %s" % oid)

    def get_rds_sg_rules(self):
        ''' Returns list of RDS SG rules. '''
        return self.rds_sg.get_sg()

    def get_rds_cidr_rules(self):
        ''' Returns list of RDS CIDR rules. '''
        return self.rds_sg.get_cidr()

    def read_rds_pg_config(self):
        ''' Reads RDS parameters from ini files. '''
        for param in self.ini.items('rds_parameters'):
            if re.match('.*parameter', param[0]):
                (name, value, method) = param[1].split()
                self.rds_pg.add_parameter((name, value, method))

    def get_rds_parameters(self):
        ''' Returns list of RDS parameters. '''
        return self.rds_pg.get_parameters()

    def read_rds_config(self):
        ''' Reads RDS config items from config and store into dictionary. '''
        for item in self.ini.items('rds_provision'):
            if item[1] == 'False':
                self.rds.add_config(item[0], None)
            else:
                self.rds.add_config(item[0], item[1])

    def get_rds_config(self):
        ''' Returns dictonary of RDS config items. '''
        return self.rds.get_config()
