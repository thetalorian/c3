''' This module is used for interfacing with AWS S3 '''
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
import kloudi.utils.tagger


class KloudiS3Bucket(object):
    ''' This class is used to interface with S3 '''
    def __init__(self, conn, bucket):
        self.conn = conn
        self.bucket = bucket
        if self.bucket_lookup() is False:
            self.create_bucket()

    def bucket_lookup(self):
        ''' Lookup to see if bucket exists '''
        try:
            if self.conn.lookup(self.bucket):
                return True
            else:
                return False
        except Exception:
            raise

    def create_bucket(self):
        ''' Create an S3 Bucket '''
        try:
            self.conn.create_bucket(self.bucket)
        except Exception:
            raise

    def delete_bucket(self):
        ''' Delete an S3 bucket '''
        try:
            self.conn.delete_bucket(self.bucket)
        except Exception:
            raise

    def get_bucket(self):
        ''' Returns an S3 bucket object '''
        try:
            s3_bucket = self.conn.get_bucket(self.bucket)
            return s3_bucket
        except Exception:
            raise

    def upload_policy(self, data):
        ''' Set and replace a S3 bucket policy '''
        s3_bucket = self.get_bucket()
        try:
            s3_bucket.set_policy(data)
        except Exception:
            raise

    def set_tags(self, tagset, verbose):
        ''' Set the cost tags for a bucket '''
        try:
            tagger = kloudi.utils.tagger.Tagger(self.conn, verbose=verbose)
            tagger.add_tags([self.bucket], tagset)
        except Exception:
            raise
