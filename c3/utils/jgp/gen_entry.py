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
import os
import re
import ConfigParser


def read_config(config):
    ''' Read in config ini file for policies '''
    ini = ConfigParser.ConfigParser()
    try:
        ini.read(config)
    except Exception:
        raise
    return ini


def gen_s3_entry(ini, user, user_account):
    ''' Generate entries from config
    >>> ini = read_config(CONFIG)
    >>> gen_s3_entry(ini, 'devzzz', 'opsqa')
    ['Allow|s3:get*,s3:list*|devzzz|opsqa|mybucket/*\
|IpAddress,aws:SourceIp,216.1.187.128/27', \
'Allow|s3:putObject|devzzz|opsqa|mybucket/foo/bar/baz|empty', \
'Deny|s3:*|devzzz|opsqa|mybucket/foobar/barbaz|empty']
    '''
    entry = []
    pattern = re.compile("path")
    for action in ini.sections():
        try:
            effect = ini.get(action, 'effect')
        except Exception:
            raise
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

if __name__ == '__main__':
    import doctest
    CONFIG = '%s/test/opsqa-devzzz.ini' % os.getenv('AWS_BASE_DIR')
    doctest.testmod()
