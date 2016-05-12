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
''' Returns entries read in from config files to be used
to generates statement policies'''
import re
import sys
import ConfigParser
from c3.utils import logging


def read_config(config):
    ''' Read in config ini file for policies '''
    ini = ConfigParser.ConfigParser()
    ini.read(config)
    if ini.sections():
        return ini
    else:
        return False


def gen_s3_entry(ini, user, user_account):
    ''' Generate entries from config '''
    entry = list()
    pattern = re.compile("path")
    if ini.sections():
        for action in ini.sections():
            try:
                effect = ini.get(action, 'effect')
            except ConfigParser.NoOptionError, msg:
                logging.warn(msg)
            if ini.has_option(action, 'condition'):
                condition = ini.get(action, 'condition')
            else:
                condition = 'empty'
            for item in ini.items(action):
                if pattern.match(item[0]):
                    path = item[1]
                    entry.append('%s|%s|%s|%s|%s|%s' % (effect, action, user,
                                                        user_account, path,
                                                        condition))
    return sorted(entry)
