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
from ConfigParser import SafeConfigParser
import ConfigParser


def verbose_msg(message, verbose):
    ''' Function for verbose output. '''
    if verbose:
        print 'DEBUG: %s' % message


class InvalidCIDRNameError(Exception):
    ''' Returns exception for inavlid CIDR names '''
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


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


class Config(SafeConfigParser):
    ''' Lets override some of the initial config loading stuff
    so we can hit he ground running '''
    def __init__(self):
        SafeConfigParser.__init__(self)
        self.read(os.getenv('AWS_CONF_DIR') + '/aws_automation.cfg')

class EBSConfig(object):
    """ a class to hold EBS configuration data"""
    def __init__(self):
        self.volumes = []

    def addVolumes(self, type, device, size, iops):
        self.volumes.append({'type': type, 'device': device, 'size': size, 'iops': iops})

    def getVolumes(self):
        return self.volumes

        self.azs = []

    # EBSConfig.setAZs()
    def setAZs(self, azs):
        self.azs = azs

    def getAZs(self):
        return self.azs

class ELBConfig(object):
    """
    a simple class to hold ELB configuration data
    """
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


        # Run-time; AZs in config can't be trusted as some may be skipped
        self.azs = []

    def validate(self):
        if not self.enabled:
            return self.enabled
        for item in ['protocol', 'public_port', 'private_port', 'hc_access_point', 'hc_interval', 'hc_target', 'hc_healthy_threshold', 'hc_unhealthy_threshold', 'vip_number']:
            if getattr(self, item) is None:
                print >> sys.stderr, "WARNING: %s not set, disabling ELB" % item
                self.enabled = False
        return self.enabled


    # ELBConfig.setAZs()
    def setAZs(self, azs):
        self.azs = azs


    def getAZs(self):
        return self.azs


class SGConfig(object):
    def __init__(self):
        self.cidr_rules = []
        self.sg_rules = []

    def addCIDR(self, proto, fport, lport, cidr):
        self.cidr_rules.append({'proto': proto, 'fport': fport, 'lport': lport, 'cidr': cidr})

    def addSG(self, proto, fport, lport, owner, sg):
        self.sg_rules.append({'proto': proto, 'fport': fport, 'lport': lport, 'owner': owner, 'sg': sg})

    def getCIDR(self):
        return self.cidr_rules

    def getSG(self):
        return self.sg_rules


class RAIDConfig(object):
    """ a simple class to hold RAID configuration data """
    def __init__(self):
        self.enabled = None
        self.level= None
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
    """ a class to hold and manage cluster configuration data
    Config will come from all of the following, in priority order:
    1) The command line, via the Set methods
    2) The Class config file, named $env$class.*\.ini
    3) The $AWS_CONF_DIR/cluster_defaults.ini.$AWS_PROFILE_NAME
    4) The $AWS_CONF_DIR/cluster_defaults.ini
    5) The $HOME/.cluster_defaults.ini (for "sshkey" only)
    >>> cc.getAMI()[:3]
    'ami'
    >>> cc.getAZs()
    ['us-east-1a', 'us-east-1b', 'us-east-1c', 'us-east-1d']
    >>> cc.getCount()
    1
    >>> cc.getSize()
    't1.micro'
    >>> cc.setAMI('ami-wil')
    >>> cc.getAMI()
    'ami-wil'
    >>> cc.setSize('m7.huge')
    >>> cc.getSize()
    'm7.huge'
    >>> cc.setCount(7)
    >>> cc.getCount()
    7
    >>> cc.setAZs("us-east-1c,us-east-1b")
    >>> cc.getAZs()
    ['us-east-1c', 'us-east-1b']
    >>> cc.getCountAZs()
    2
    >>> cc.setAZs("us-east-1c,us-east-1b,us-east-1b")
    >>> cc.getCountAZs()
    2
    >>> cc.getDC()
    'aws1'
    >>> cc.getTagset() # doctest: +ELLIPSIS
    {'BusinessUnit': 'CityGrid', 'Project': 'CloudTest', 'Component': 'pro ProvisionTestBox', 'Env': 'dev', 'Team': 'Operations'}
    >>> cc.getLaunchTimeout()
    180
    >>> cc.getSleepStep()
    10
    >>> cc.getUserDataFile() # doctest: +ELLIPSIS
    '/.../bin/userdata.pl'
    >>> cc.getAdditionalSGs()
    ['ssg-management']
    >>> cc.addSG("sg-other")
    >>> cc.getAdditionalSGs()
    ['ssg-management', 'sg-other']
    >>> cc.getNodeGroups()
    ['default_install', 'pro']
    >>> cc.getAllocateEIPs()
    False
    >>> cc.setAllocateEIPs()
    True
    >>> cc.getAllocateEIPs()
    True
    >>> cc.getUseEBSOptimized()
    False
    """
    def __init__(self, file=None, account_name=None, overrides={},
                 verbose=False, no_defaults=False):
        self.no_defaults = no_defaults  # only read self.classfile if True
        self.defaults = os.getenv('AWS_CONF_DIR') + '/cluster_defaults.ini'
        # This should hold only the ssh key
        self.personal_defaults = os.getenv('HOME') + '/.cluster_defaults.ini'
        self.classfile = file
        if not os.path.exists(file):
            raise ConfigNotFoundException("Can't find config: %s" % file);
        self.verbose = verbose
        self.account_name = account_name
        # TODO: remove once all programs are moved to zambi
        if not self.account_name:
            import cgm.utils.account_utils
            self.account_name = cgm.utils.account_utils.getAccount()
        self.primary_sg = None
        # These aren't IN the config file, they're implied by the name
        self.server_env = None
        self.server_class = None
        # this should be looked up from the AZs used
        self.server_datacenter = None
        self.user_data_raw = None
        self.domain = None
        self.ebs = EBSConfig()
        self.elb = ELBConfig()
        self.sg = SGConfig()
        self.raid = RAIDConfig()
        self.rds = RDSInstanceConfig()
        self.rds_sg = RDSSGConfig()
        self.rds_pg = RDSPGConfig()
        self.overrides = {}
        # Read the in the INI files
        if self.no_defaults:
            self.readFiles([self.classfile])
        else:
            self.readFiles(
                [self.personal_defaults, self.defaults,
                "%s-%s" % (self.defaults, self.account_name), self.classfile])
        self.getMetaData()
        self.server_datacenter = self.getCGRegion()
        if self.ini.has_section('ebs'):
            self.readEBSConfig()
        if self.ini.has_section('elb'):
            self.readELBConfig()
        if self.ini.has_section('securitygroup'):
            self.readSGConfig()
        if self.ini.has_section('raid'):
            self.readRAIDConfig()
        if self.ini.has_section('rds_provision'):
            self.read_rds_config()
        if self.ini.has_section('rds_securitygroup'):
            self.read_rds_sg_config()
        if self.ini.has_section('rds_parameters'):
            self.read_rds_pg_config()

    def getMetaData(self):
        self.server_env = os.path.basename(self.classfile)[:3]
        self.server_class = os.path.basename(self.classfile)[3:6]
        self.primary_sg = "%s%s" % (self.server_env, self.server_class)
        self.global_ssg = 'ssg-management'

    def getServerEnv(self):
        return self.server_env

    def getPrimarySG(self):
        return self.primary_sg

    def getGlobalSSG(self):
        return self.global_ssg

    def getAWSRegion(self):
        # we should only work in one region, so we can just take the first
        if self.getAZs()[0] == 'auto':
            return 'us-east-1'
        else:
            return self.getAZs()[0][:-1]

    # FIXME TODO this should use cgm.utils.cgm_naming.getAmazonDatacenter()
    def getCGRegion(self):
        # we should only work in one region, so we can just take the first
        if not self.getAZs():
            return 'aws1'
        if self.getAZs()[0] == 'auto':
            return 'aws1'
        if self.getAZs()[0][:-1] == 'us-east-1':
            return 'aws1'
        if self.getAZs()[0][:-1] == 'us-west-1':
            return 'aws2'
        raise InvalidAZError("AZ '%s' is invalid" % self.getAZs()[0])

    def readFiles(self, files):
        self.files = []
        for file in files:
            if os.path.exists(file):
                self.files.append(file)
        if self.verbose:
            print >> sys.stderr, "Trying %s\n" % files
            print >> sys.stderr, "Read %s\n" % self.files
        self.ini = ConfigParser.ConfigParser(
            {"AWS_CONF_DIR": os.getenv('AWS_CONF_DIR')})
        self.ini.read(files)

    # get a setting from the INI files
    def getIni(self, section, name, castf, fallback=None):
        if self.ini.has_option(section, name):
            try:
                return castf(self.ini.get(section, name))
            except Exception, e:
                print >> sys.stderr, e
        return fallback

    def get_hvm_instances(self):
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

    def setAMI(self, ami):
        self.overrides['ami'] = ami

    def getAMI(self):
        if 'ami' in self.overrides:
            return self.overrides['ami']
        instance_type = self.getSize()
        raw_ami = self.getIni('cluster', 'ami', str, None)
        if raw_ami.count('VTYPE'):
            if instance_type in self.get_hvm_instances():
                return raw_ami.replace('VTYPE', 'hvm')
            else:
                return raw_ami.replace('VTYPE', 'paravirtual')
        else:
            return raw_ami

    def getWhitelistURL(self):
        if 'whitelisturl' in self.overrides:
            return self.overrides['whitelisturl']
        return self.getIni("cluster", "whitelisturl", str, None)

    def getResolvedAMI(self, nvdb, verbose=False):
        ami = self.getAMI()
        if ami[:4] == 'ami-':
            print >> sys.stderr, "WARNING: AMI statically set to %s. Please use nv graffiti values" % ami
            return ami

        try:
            amis = nvdb.getAMIs(self.getCGRegion(), ami)
        except Exception, e:
            #print >> sys.stderr, "FATAL: could not determine AMI (%s)" % e
            raise AMINotFoundError("nv query for '%s' failed" % ami)
        if amis is None:
            raise AMINotFoundError("No AMI matching '%s' found" % ami)
        if len(amis) == 1:
            newami = amis.values()[0]
            self.setAMI(newami)
            if verbose:
                print >> sys.stderr, "INFO: Converted '%s' to '%s'" % (ami, newami)
            return newami
        elif len(amis) > 1:
            raise TooManyAMIsError("%s matches too many AMIs" % ami, amis)

    def limitAZs(self, limit):
        if limit > 0:
            oldazs = self.getAZs()
            newazs = oldazs[:limit]
            self.setAZs(','.join(newazs))
            return len(oldazs) - len(newazs)
        else:
            print >> sys.stderr, "WARNING: trying to limit AZs to %d" % limit
        return 0

    # set comma-separated list
    def setAZs(self, azs):
        for az in azs.split(","):
            if not self._verifyAZ(az):
                raise InvalidAZError("AZ '%s' is invalid" % az)
        self.overrides['azs'] = azs.split(",")

    def _verifyAZ(self, az):
        if re.match("^\w\w-\w\wst-\d\w", az):
            return True
        return False

    def getAZs(self):
        if 'azs' in self.overrides:
            return self.overrides['azs']
        ret = self.getIni("cluster", "zone", str, "")
        if ret:
            for az in ret.split(","):
                if not self._verifyAZ(az):
                    raise InvalidAZError("AZ '%s' is invalid" % az)
            return map(str.strip, ret.split(","))
        return []

    # is this safe? It changes the order of the main list as we go; copy better?
    def getNextAZ(self):
        # we'll need them in a list to do this, stick in overrides
        if 'azs' not in self.overrides:
            self.overrides['azs'] = self.getAZs()
        try:
            az = self.overrides['azs'].pop(0)
            self.overrides['azs'].append(az)
            return az
        except:
            return None

    def getCountAZs(self):
        """ get the count of unique AZs """
        return len(set(self.getAZs()))

    def setCount(self, count):
        self.overrides['count'] = int(count)

    def getCount(self):
        if 'count' in self.overrides:
            return self.overrides['count']
        return self.getIni("cluster", "instance_count", int, None)

    def setSize(self, size):
        self.overrides['size'] = size

    def getSize(self):
        if 'size' in self.overrides:
            return self.overrides['size']
        return self.getIni("cluster", "instance_size", str, None)

    def setSSHKey(self, sshkey):
        self.overrides['sshkey'] = sshkey

    def getSSHKey(self):
        if 'sshkey' in self.overrides:
            return self.overrides['sshkey']
        return self.getIni("ssh", "sshkey", str, None)

    def getDC(self):
        if self.getIni("DEFAULT", "datacenter", str, None) is not None:
            print >> sys.stderr, "WARNING: the 'datacenter' option is no longer read from the INI file"
        return self.getCGRegion()

    def getUserDataFile(self):
        return self.getIni("cluster", "user_data_file", str, None)

    def getUserData(self, replacements={}):
        path = self.getUserDataFile()
        if not self.user_data_raw:
            if os.path.exists(path):
                try:
                    fp = file(path, "r")
                    self.user_data_raw = fp.read()
                    fp.close()
                except:
                    print >> sys.stderr, "ERROR: failed to read user data from %s" % path
                    return None
        ud = self.user_data_raw
        for k in replacements.keys():
            if self.verbose:
                print (
                    'DEBUG: replacing %s with %s in %s' %
                    (k, replacements[k], path))
            ud = ud.replace(k, replacements[k])
        return ud

    def getTagset(self):
        self.tagset = {}
        self.tagset['BusinessUnit'] = self.getIni("tags", "business_unit", str, None)
        self.tagset['Team'] = self.getIni("tags", "team", str, None)
        self.tagset['Project'] = self.getIni("tags", "project", str, None)
        if any(e for e in self.files if e.endswith('meta.ini')):
            self.tagset['Component'] = self.getIni("tags", "component", str, None)
        else:
            c = self.getIni("tags", "component", str, self.server_class)
            if c[:4] == self.server_class + " ":
                self.tagset['Component'] = self.getIni("tags", "component", str, self.server_class)
            else:
                self.tagset['Component'] = "%s %s" % (self.server_class, self.getIni("tags", "component", str, self.server_class))
        if self.getIni("tags", "env", str, None):
            self.tagset['Env'] = self.getIni("tags", "env", str, None)
        else:
            self.tagset['Env'] = self.server_env
        return self.tagset

    def getLaunchTimeout(self):
        return self.getIni("cluster", "launch_timeout", int, None)

    def getSleepStep(self):
        return self.getIni("cluster", "sleep_step", int, None)

    def addSG(self, sg):
        if 'other_sgs' not in self.overrides:
            self.overrides['other_sgs'] = self.getAdditionalSGs()
        self.overrides['other_sgs'].append(sg)

    def getAdditionalSGs(self):
        if 'other_sgs' in self.overrides:
            return self.overrides['other_sgs']
        ret = self.getIni("cluster", "additional_sgs", str, None)
        if ret:
            return map(str.strip, ret.split(","))
        return []

    # get the Primary SG and the Additional SGs
    def getSGs(self):
        ret = self.getAdditionalSGs()
        ret.append("%s%s" % (self.server_env, self.server_class))
        return ret

    def getNodeGroups(self):
        if 'node_groups' in self.overrides:
            return self.overrides['node_groups']
        ret = self.getIni("cluster", "node_groups", str, None)
        if ret:
            return map(str.strip, ret.split(","))
        return []

    def setAllocateEIPs(self):
        self.overrides['allocate_eips'] = True
        return True

    def getAllocateEIPs(self):
        if 'allocate_eips' in self.overrides:
            return self.overrides['allocate_eips']
        if self.getIni("cluster", "allocate_eip", str, None) == "True":
            self.allocate_eips = True
        else:
            self.allocate_eips = False
        return self.allocate_eips

    def setUseEBSOptimized(self):
        self.overrides['use_ebs_optimized'] = True
        return True

    def getUseEBSOptimized(self):
        if 'use_ebs_optimized' in self.overrides:
            return self.overrides['use_ebs_optimized']
        if self.getIni("cluster", "use_ebs_optimized", str, None) == "True":
            self.use_ebs_optimized = True
        else:
            self.use_ebs_optimized = False
        return self.use_ebs_optimized

    def get_aws_account(self):
        ''' Returns AWS account name. '''
        return self.account_name

    def get_domain(self):
        ''' Returns domain '''
        return self.getIni('cluster', 'domain', str, None)

    def get_fs_type(self):
        ''' Get the filesystem type '''
        return self.getIni('cluster', 'fs_type', str, None)

    def readEBSConfig(self):
        if not self.ini.has_section("ebs"):
            return False
        import cgm.aws.ec2.ebs
        for v in self.ini.items("ebs"):
            if len(v[1].split()) == 3:
                self.device = v[0]
                (self.type, self.size, self.iops) = v[1].split(" ")
                self.ebs.addVolumes(self.type, "/dev/" + self.device, self.size, self.iops)
            elif len(v[1].split()) == 2:
                self.device = v[0]
                (self.type, self.size) = v[1].split(" ")
                self.ebs.addVolumes(self.type, "/dev/" + self.device, self.size, None)
        return True

    def getEBSConfig(self):
        return self.ebs.getVolumes()

    def readELBConfig(self):
        if self.getIni("elb", "enabled", str, None) == "True":
            self.elb.enabled = True
        else:
            self.elb.enabled = False
            return False

        self.elb.protocol = self.getIni("elb", "protocol", str, None)
        self.elb.public_port = self.getIni("elb", "public_port", int, None)
        self.elb.private_port = self.getIni("elb", "private_port", int, None)

        self.elb.vip_number = self.getIni("elb", "vip_number", int, None) or 1

        self.elb.hc_access_point = self.getIni("healthcheck", "hc_access_point", str, None)
        self.elb.hc_interval = self.getIni("healthcheck", "hc_interval", int, None)
        self.elb.hc_target = self.getIni("healthcheck", "hc_target", str, None)
        self.elb.hc_healthy_threshold = self.getIni("healthcheck", "hc_healthy_threshold", int, None)
        self.elb.hc_unhealthy_threshold = self.getIni("healthcheck", "hc_unhealthy_threshold", int, None)

        self.elb.validate()

    # we said only use the getters, so here it is for ELB
    def getELBConfig(self):
        return self.elb

    def getELBName(self):
        """
        Return the name of the ELB, based on cluster and ELB configs
        >>> cc.readELBConfig()
        >>> cc.getELBName()
        'aws1dvippro1'
        """
        return "%s%svip%s%d" % (self.getCGRegion(), self.server_env[:1], self.server_class, self.elb.vip_number)

    def readSGConfig(self):
        import cgm.utils.cgm_naming
        import cgm.utils.account_utils
        for c in self.ini.items("securitygroup"):
            if c[1][:7] == "ingress":
                (type, proto, ports, remote) = c[1].split(" ")
                if ports == "None":
                    (p1, p2) = [-1, -1]
                else:
                    try:
                        (p1, p2) = ports.split("-")
                    except:
                        p1 = p2 = ports
                p1 = int(p1)
                p2 = int(p2)
                if remote[:5] == 'CIDR:':
                    self.sg.addCIDR(proto, p1, p2, remote[5:])
                elif remote[:4] == 'Net:':
                    cidr = cgm.utils.cgm_naming.getCIDR(remote[4:])
                    if not cidr:
                        raise InvalidCIDRNameError("Network '%s' is invalid" % remote[4:])
                    self.sg.addCIDR(proto, p1, p2, cidr)
                elif remote[:3] == 'SG:':
                    acct, sg = remote[3:].split("/")
                    if acct != 'self':
                        acctid = cgm.utils.account_utils.getAccountID(acct)
                        if self.verbose:
                            print "INFO: %s == %s" % (acct, acctid)
                    else:
                        acctid = cgm.utils.account_utils.getAccountID(
                            self.get_aws_account())
                    if acctid:
                        self.sg.addSG(proto, p1, p2, acctid, sg)
                    else:
                        print "WARN: Can't find my own account."
                if self.verbose:
                    print >> sys.stderr, "INFO: Opening %s for ports %d to %d from %s" % (proto, p1, p2, remote)

    def getSGRules(self):
        return self.sg.getSG()

    def getCIDRRules(self):
        return self.sg.getCIDR()

    def readRAIDConfig(self):
        if not self.ini.has_section("raid"):
            self.raid.enabled = False
            return False
        if self.getIni("raid", "enabled", str, None) == "True":
            self.raid.enabled = True
        else:
            self.raid.enabled = False
            return False
        self.raid.level= self.getIni("raid", "level", str, None)
        self.raid.device = self.getIni("raid", "device", str, None)

    def read_rds_sg_config(self):
        ''' Reads RDS SG authorizations from ini files. '''
        import cgm.utils.cgm_naming
        import cgm.utils.account_utils
        for rule in self.ini.items('rds_securitygroup'):
            if re.match('.*rule', rule[0]):
                (rtype, rvalue) = rule[1].split(':')
                if rtype == 'Net':
                    cidr = cgm.utils.cgm_naming.getCIDR(rvalue)
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
                        acctid = cgm.utils.account_utils.getAccountID(oid)
                    else:
                        acctid = cgm.utils.account_utils.getAccountID(
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

    # Not used yet
    def getPreferredAZs(self):
        print >> sys.stderr, "preferred AZs are not yet implemented"
        ret = self.getIni("cluster", "preferred_zone", str, "")
        if ret:
            return map(str.strip, ret.split(","))
        return []


def get_account_from_conf(conf=None):
    ''' Loads config only so we can get the account for ClusterConfig. '''
    scp = SafeConfigParser()
    if not os.path.exists(conf):
        raise ConfigNotFoundException("Can't find config: %s" % conf);
    scp.read(conf)
    return scp.get('cluster', 'aws_account')


if __name__ == '__main__':
    import doctest
    test_ini = os.getenv('AWS_CONF_DIR') + '/devpro.ini'
    doctest.testmod(extraglobs={'cc': ClusterConfig(test_ini, 'opsqa', True)})
