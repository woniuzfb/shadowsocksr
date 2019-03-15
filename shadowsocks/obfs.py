#!/usr/bin/env python
#
# Copyright 2015-2015 breakwa11
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging

from shadowsocks import common
from shadowsocks.obfsplugin import plain, http_simple, obfs_tls, verify, auth, auth_chain


method_supported = {}
method_supported.update(plain.obfs_map)
method_supported.update(http_simple.obfs_map)
method_supported.update(obfs_tls.obfs_map)
method_supported.update(verify.obfs_map)
method_supported.update(auth.obfs_map)
method_supported.update(auth_chain.obfs_map)

def mu_protocol():
    return ["auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a"]

class server_info(object):
    def __init__(self, data):
        self.data = data

class obfs(object):
    def __init__(self, method):
        self.method = method
       
    
    def get_obfs(self):
        method = self.method.lower()
        m = method_supported.get(method)
        
        if m:
            return m[0](method)
        else:
            raise Exception('obfs plugin [%s] not supported' % method)
        