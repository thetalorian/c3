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
''' Organize options from config files'''
import os
import re
import sys
import ConfigParser
import c3.aws.ec2.ebs
import c3.utils.naming
import c3.utils.accounts
from ConfigParser import SafeConfigParser


def verbose_msg(message, verbose):
    ''' Function for verbose output. '''
    if verbose:
        print 'DEBUG: %s' % message


def error_msg(message):
    ''' Prints message to stderr '''
    print >> sys.stderr, 'ERROR: %s' % message


def get_account_from_conf(conf=None):
    ''' Loads config only so we can get the account for ClusterConfig. '''
    scp = SafeConfigParser()
    scp.read(conf)
    try:
        return scp.get('cluster', 'aws_account')
    except ConfigParser.NoSectionError, msg:
        error_msg(msg)
        sys.exit(1)
    except ConfigParser.NoOptionError, msg:
        error_msg(msg)
        sys.exit(1)


class TooManyAMIsError(Exception):
    ''' Returns too many AMI exception '''
    def __init__(self, value, amis):
        self.value = value
        self.amis = amis

    def __str__(self):
        return repr(self.value)


class AMINotFoundError(Exception):
    ''' Return AMI not found exception '''
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class InvalidAZError(Exception):
    ''' Returns invalid AZ exception'''
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class InvalidCIDRNameError(Exception):
    ''' Return invalid cidr name exception '''
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class ConfigNotFoundException(Exception):
    ''' Return config not found exception '''
    def __init__(self, value):
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
                error_msg(msg)
                self.enabled = False
        return self.enabled

    def set_azs(self, azs):
        ''' Set ELB AZ '''
        self.azs = azs

    def get_az2(self):
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
    def __init__(self, ini_file=None, account_name=None, overrides={},
                 verbose=False, no_defaults=False):
        self.no_defaults = no_defaults  # only read self.classfile if True
        self.defaults = os.getenv('AWS_CONF_DIR') + '/cluster_defaults.ini'
        # This should hold only the ssh key
        self.personal_defaults = os.getenv('HOME') + '/.cluster_defaults.ini'
        self.classfile = ini_file
        if not os.path.exists(ini_file):
            raise ConfigNotFoundException("Can't find config: %s" % ini_file)
        self.verbose = verbose
        self.account_name = account_name
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
        self.overrides = dict()
        # Read the in the INI files
        if self.no_defaults:
            self.read_files([self.classfile])
        else:
            self.read_files(
                [self.personal_defaults, self.defaults,
                 "%s-%s" % (self.defaults, self.account_name), self.classfile])
        self.get_meta_data()
        self.server_datacenter = self.get_cg_region()
        if self.ini.has_section('ebs'):
            self.read_ebs_config()
        if self.ini.has_section('elb'):
            self.read_elb_config()
        if self.ini.has_section('securitygroup'):
            self.read_sg_config()
        if self.ini.has_section('raid'):
            self.read_raid_config()
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

    # Why do we have two?
    def get_aws_region(self):
        ''' We work in only one region, so we can just take the first '''
        if self.get_azs()[0] == 'auto':
            return 'us-east-1'
        else:
            return self.get_azs()[0][:-1]

    # This is the other one...
    def get_cg_region(self):
        ''' Return region from c3.utils.naming.get_aws_dc '''
        return c3.utils.naming.get_aws_dc(self.region)

    def read_files(self, ini_files):
        ''' Read in ini files '''
        self.ini_files = list()
        verbose_msg('Trying %s\n' % ini_files, self.verbose)
        for ini in ini_files:
            if os.path.exists(ini):
                self.ini_files.append(ini)
        verbose_msg('Read %s\n' % self.files, self.verbose)
        self.ini = ConfigParser.ConfigParser(
            {"AWS_CONF_DIR": os.getenv('AWS_CONF_DIR')})
        self.ini.read(ini_files)

    def get_ini(self, section, name, castf):
        ''' Get a setting from the ini files '''
        try:
            return castf(self.ini.get(section, name))
        except ConfigParser.NoSectionError, msg:
            error_msg(msg)
            return None
        except ConfigParser.NoOptionError, msg:
            error_msg(msg)
            return None

    def get_hvm_instances(self):
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
            if instance_type in self.get_hvm_instances():
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

    def get_resolved_ami(self, nvdb):
        ''' Return resolved AMI '''
        ami = self.get_ami()
        if ami[:4] == 'ami-':
            error_msg(
                'AMI statically set to %s. Please use nv graffiti values' % ami)
            return ami
        amis = nventory.get_amis(self.get_cg_region(), ami)
        if amis is None:
            raise AMINotFoundError("No AMI matching '%s' found" % ami)
        if len(amis) == 1:
            newami = amis.values()[0]
            self.set_ami(newami)
            verbose_msg("Converted '%s' to '%s'" % (ami, newami), self.verbose)
            return newami
        elif len(amis) > 1:
            raise TooManyAMIsError("%s matches too many AMIs" % ami, amis)

    def limit_azs(self, limit):
        ''' Limit the number of AZs to use '''
        if limit > 0:
            oldazs = self.get_azs()
            newazs = oldazs[:limit]
            self.set_azs(','.join(newazs))
            return len(oldazs) - len(newazs)
        else:
            error_msg("Trying to limit AZs to %d" % limit)
        return 0

    def set_azs(self, azs):
        ''' Set comma sperated list of AZs '''
        for avz in azs.split(","):
            if not self._verify_az(avz):
                raise InvalidAZError("AZ '%s' is invalid" % avz)
        self.overrides['azs'] = azs.split(",")

    def _verify_az(self, avz):
        ''' Verify AZ via regex '''
        if re.match(r"^\w\w-\w\wst-\d\w", avz):
            return True
        return False

    def get_azs(self):
        ''' Return AZ information '''
        if 'azs' in self.overrides:
            return self.overrides['azs']
        ret = self.get_ini("cluster", "zone", str)
        if ret:
            for avz in ret.split(","):
                if not self._verify_az(avz):
                    raise InvalidAZError("AZ '%s' is invalid" % avz)
            return map(str.strip, ret.split(","))
        return list()

    def get_next_az(self):
        ''' We'll need them in a list to do this, stick in overrides '''
        if 'azs' not in self.overrides:
            self.overrides['azs'] = self.get_azs()
        try:
            avz = self.overrides['azs'].pop(0)
            self.overrides['azs'].append(avz)
            return az
        except IndexError, msg:
            error_msg(msg)
            return None

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
            error_msg(
                "The 'datacenter' option is no longer read from the INI file")
        return self.get_cg_region()

    def get_user_data_file(self):
        ''' Return the userdata file '''
        return self.get_ini("cluster", "user_data_file", str)

    def get_user_data(self, replacements={}):
        ''' Get userdata and set replacements '''
        path = self.get_user_data_file()
        if not self.user_data_raw:
            if os.path.exists(path):
                try:
                    fpath = file(path, "r")
                    self.user_data_raw = fpath.read()
                    fpath.close()
                except IOError, msg:
                    error_msg(msg)
                    return None
        udata = self.user_data_raw
        for key in replacements.keys():
            verbose_msg(
                'Replacing %s with %s in %s' %
                (key, replacements[key], path), self.verbose)
            udata = udata.replace(key, replacements[key])
        return udata

    def get_tagset(self):
        ''' Return the tagset cost tags '''
        self.tagset = dict()
        self.tagset['BusinessUnit'] = self.get_ini("tags", "business_unit", str)
        self.tagset['Team'] = self.get_ini("tags", "team", str)
        self.tagset['Project'] = self.get_ini("tags", "project", str)
        if any(ent for ent in self.ini_files if ent.endswith('meta.ini')):
            self.tagset['Component'] = self.get_ini("tags", "component", str)
        else:
            comp = self.get_ini("tags", "component", str)
            if comp[:4] == self.server_class + ' ':
                self.tagset['Component'] = self.get_ini(
                    "tags", "component", str)
            else:
                self.tagset['Component'] = "%s %s" % (
                    self.server_class, self.get_ini("tags", "component", str))
        if self.get_ini("tags", "env", str):
            self.tagset['Env'] = self.get_ini("tags", "env", str)
        else:
            self.tagset['Env'] = self.server_env
        return self.tagset

    def get_launch_timeout(self):
        ''' Return launch timeout '''
        return self.get_ini("cluster", "launch_timeout", int)

    def get_sleep_step(self):
        ''' Return sleep step '''
        return self.get_ini("cluster", "sleep_step", int)

    def add_sg(self, sgp):
        ''' Adding additional SGs '''
        if 'other_sgs' not in self.overrides:
            self.overrides['other_sgs'] = self.get_additional_sgs()
        self.overrides['other_sgs'].append(sgp)

    def get_additional_sgs(self):
        ''' Returns additonal SGs'''
        if 'other_sgs' in self.overrides:
            return self.overrides['other_sgs']
        ret = self.get_ini("cluster", "additional_sgs", str)
        if ret:
            return map(str.strip, ret.split(","))
        return list()

    def get_sgs(self):
        ''' Return all SGs '''
        ret = self.get_additional_sgs()
        ret.append("%s%s" % (self.server_env, self.server_class))
        return ret

    def get_node_groups(self):
        ''' Return Node groups '''
        if 'node_groups' in self.overrides:
            return self.overrides['node_groups']
        ret = self.get_ini("cluster", "node_groups", str, None)
        if ret:
            return map(str.strip, ret.split(","))
        return list()

    def set_allocate_eips(self):
        ''' Set allocated EIPs '''
        self.overrides['allocate_eips'] = True
        return True

    def get_allocate_eips(self):
        ''' Return allocated EIPs '''
        if 'allocate_eips' in self.overrides:
            return self.overrides['allocate_eips']
        if self.get_ini("cluster", "allocate_eip", str) == "True":
            self.allocate_eips = True
        else:
            self.allocate_eips = False
        return self.allocate_eips

    def set_use_ebs_optimized(self):
        ''' Set use EBS optimized '''
        self.overrides['use_ebs_optimized'] = True

    def get_use_ebs_optimized(self):
        ''' Get EBS optimized option '''
        if 'use_ebs_optimized' in self.overrides:
            return self.overrides['use_ebs_optimized']
        if self.get_ini("cluster", "use_ebs_optimized", str):
            self.use_ebs_optimized = True
        else:
            self.use_ebs_optimized = False
        return self.use_ebs_optimized

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
                self.device = vol[0]
                (self.vol_type, self.size, self.iops) = vol[1].split(" ")
                self.ebs.add_volumes(
                    self.vol_type, "/dev/" + self.device, self.size, self.iops)
            elif len(vol[1].split()) == 2:
                self.device = vol[0]
                (self.vol_type, self.size) = vol[1].split(" ")
                self.ebs.add_volumes(
                    self.vol_type, "/dev/" + self.device, self.size, None)

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
        ''' Return the name of the ELB, based on cluster and ELB configs
        >>> cc.read_elb_config()
        >>> cc.get_elb_name()
        'aws1dvippro1'
        '''
        return "%s%svip%s%d" % (
            self.get_cg_region(), self.server_env[:1],
            self.server_class, self.elb.vip_number)

    def read_sg_config(self):
        ''' Reads in SG config options '''
        for item in self.ini.items("securitygroup"):
            if item[1][:7] == "ingress":
                (type, proto, ports, remote) = item[1].split(" ")
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
                    acct, sg = remote[3:].split("/")
                    if acct != 'self':
                        acctid = c3.utils.accounts.getAccountID(acct)
                        verbose_msg('%s == %s' % (acct, acctid), self.verbose)
                    else:
                        acctid = c3.utils.accounts.getAccountID(
                            self.get_aws_account())
                    if acctid:
                        self.sgrp.add_sg(proto, prt1, prt2, acctid, sg)
                    else:
                        error_msg("Can't find my own account.")
                verbose_msg(
                    "INFO: Opening %s for ports %d to %d from %s" %
                    (proto, prt1, prt2, remote), self.verbose)

    def get_sg_rules(self):
        ''' Return SG rules '''
        return self.sgrp.get_sg()

    def get_cidr_rules(self):
        ''' Return CIDR rules '''
        return self.sgrp.get_cidr()

    def read_raid_config(self):
        ''' Read in RAID config options '''
        if self.get_ini("raid", "enabled", str) == "True":
            self.raid.enabled = True
        else:
            self.raid.enabled = False
            return False
        self.raid.level = self.get_ini("raid", "level", str)
        self.raid.device = self.get_ini("raid", "device", str)

    def read_rds_sg_config(self):
        ''' Reads RDS SG authorizations from ini files. '''
        for rule in self.ini.items('rds_securitygroup'):
            if re.match('.*rule', rule[0]):
                (rtype, rvalue) = rule[1].split(':')
                if rtype == 'Net':
                    cidr = c3.utils.naming.get_cidr(rvalue)
                    if cidr:
                        verbose_msg('Appending RDS CIDR rule %s' % cidr,
                                    self.verbose)
                        self.rds_sg.add_cidr(cidr)
                elif rtype == 'CIDR':
                    verbose_msg('Appending RDS CIDR rule %s' % rvalue,
                                self.verbose)
                    self.rds_sg.add_cidr(rvalue)
                elif rtype == 'SG':
                    (oid, sid) = rvalue.split('/')
                    if oid != 'self':
                        acctid = c3.utils.accounts.getAccountID(oid)
                    else:
                        acctid = c3.utils.accounts.getAccountID(
                            self.get_aws_account())
                    if acctid:
                        verbose_msg(
                            'Appending RDS SG rule %s:%s' % (acctid, sid),
                            self.verbose)
                        self.rds_sg.add_sg(acctid, sid)
                    else:
                        print "WARN: Can't find account for %s" % oid

    def get_rds_sg_rules(self):
        ''' Returns list of RDS SG rules. '''
        return self.rds_sg.get_sg()

    def get_rds_cidr_rules(self):
        ''' Returns list of RDS SG rules. '''
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


if __name__ == '__main__':
    import doctest
    TEST_INI = os.getenv('AWS_CONF_DIR') + '/devpro.ini'
    doctest.testmod(extraglobs={'cc': ClusterConfig(TEST_INI, 'opsqa', True)})
