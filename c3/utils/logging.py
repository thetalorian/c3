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
''' Logging interface for C3 '''
import sys
import datetime


def error(message):
    ''' Prints error messages to STDERR '''
    print >> sys.stderr, (
        '%s ERROR: %s' % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            message))


def warn(message):
    ''' Prints error messages to STDERR '''
    print >> sys.stderr, (
        '%s WARN: %s' % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            message))


def info(message):
    ''' Prints informational messages to STDOUT '''
    print >> sys.stdout, (
        '%s INFO: %s' % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            message))


def debug(message, verbose):
    ''' Prints verbose messaging to STDOUT '''
    if verbose:
        print >> sys.stdout, (
            '%s DEBUG: %s' % (
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                message))
