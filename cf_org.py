#!/usr/bin/python

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import json
import urllib

DOCUMENTATION = '''
---
module: cf_org
short_description: Manage Cloud Foundry Orgs
description:
    - Manage Cloud Foundry Orgs
author: "Paul Markham, @pmarkham"
options:
    state:
        description:
            - Desired state of the org
        required: false
        default: present
        choices: [present, absent]
    name:
        description:
            - Name of the org
        required: true
        default: null
        aliases: [id]
    admin_user:
        description:
            - Administrator username/email
        required: true
        default: null
    admin_password:
        description:
            - Administrator password
        required: true
        default: null
    domain:
        description:
            - Domain name
            - Will prepend U(login.system) and U(api.system) to this.
            - Use I(login_url) and I(api_url) if this isn't suitable.
        required: false
    login_url:
        description:
            - URL of login end point
            - Not require if I(domain) is specified
        required: false
    api_url:
        description:
            - URL of api end point
            - Not require if I(domain) is specified
        required: false
    protocol:
        description:
            - Protocol to use for API calls
        required: false
        default: https
        choices: [https, http]
    quota:
        description:
            - Name of quota to associate with the org
        required: false
        default: default
    validate_certs:
        description:
            - Validate SSL certs. Validation will fail with self-signed certificates.
        required: false
        default: false
    force:
        description:
            - Force deletion of system org
        required: false
        default: false
'''

EXAMPLES = '''
# Create org with default quota
- cf_org: state=present name=test admin_user=admin admin_password=abc123 domain=example.com

# Create org specifying quota/change quota of existing org
- cf_org: state=present name=test admin_user=admin admin_password=abc123 quota=runaway domain=example.com

# Delete org
- cf_org: state=absent name=test admin_user=admin admin_password=abc123 domain=example.com
'''

class CF_Org(object):
    def __init__(self, module):
        self.exists       = False
        self.http_headers = {}

        self.result = {
            'changed': False,
            'diff': {},
            'msg': [],
        }

        self.module         = module
        self.name           = self.module.params['name']
        self.admin_user     = self.module.params['admin_user']
        self.admin_password = self.module.params['admin_password']
        self.domain         = self.module.params['domain']
        self.protocol       = self.module.params['protocol']
        if self.module.params['login_url']:
            self.login_url = '%s://%s' % (self.protocol, self.module.params['login_url'])
        else:
            self.login_url = '%s://login.system.%s' % (self.protocol, self.domain)
        if self.module.params['api_url']:
            self.api_url = '%s://%s' % (self.protocol, self.module.params['api_url'])
        else:
            self.api_url = '%s://api.system.%s' % (self.protocol, self.domain)
        self.quota          = self.module.params['quota']
        self.validate_certs = self.module.params['validate_certs']
        self.force          = self.module.params['force']

        if self.module.check_mode:
            self.result['msg'].append('*** Running in check mode ***')

        self.login()
        self.get_org()

    def present(self):
        self.get_quota_guid()
        if self.exists:
            self.result['msg'].append("Org '%s' already exists" % self.name)
            if self.org_quota_guid != self.quota_guid:
                self.update_quota()
        else:
            self.create_org()

    def absent(self):
        if self.exists:
            self.delete_org()
        else:
            self.result['msg'].append("Org '%s' doesn't exist" % self.name)

    def login(self):
        action = 'Login'
        url = '%s/oauth/token' % self.login_url
        credentials = 'username=%s&password=%s&client_id=cf&grant_type=password&response_type=token' % (self.admin_user, self.admin_password)
        self.http_headers['Authorization'] = 'Basic %s' % base64.b64encode("%s:%s" % ('cf', ''))
        response, info = fetch_url(self.module, url, data=credentials, headers=self.http_headers, method='POST')
        if info['status'] == 200:
            self.access_token = json.loads(response.read())['access_token']
            self.exists = True
        else:
            self.api_error(action, info)
        self.http_headers['Authorization'] = 'bearer %s' % self.access_token
        self.http_headers['Content-Type'] = 'application/json'

    def get_org(self):
        action = "Get org '%s'" % self.name
        url = '%s/v2/organizations?q=%s' % (self.api_url, urllib.quote('name:%s' % self.name))
        response, info = fetch_url(self.module, url, headers=self.http_headers, method='GET')
        if info['status'] == 200:
            r = json.loads(response.read())
            num = int(r['total_results'])
            if num == 0:
                self.exists = False
            else:
                self.exists = True
                self.org_guid = r['resources'][0]['metadata']['guid']
                self.org_quota_guid = r['resources'][0]['entity']['quota_definition_guid']
        else:
            self.api_error(action, info)

    def get_quota_guid(self):
        action = "Get quote guid '%s'" % self.quota
        url = '%s/v2/quota_definitions?q=%s' % (self.api_url, urllib.quote('name:%s' % self.quota))
        response, info = fetch_url(self.module, url, headers=self.http_headers, method='GET')
        if info['status'] == 200:
            r = json.loads(response.read())
            num = int(r['total_results'])
            if num == 0:
                self.module.fail_json(msg="Quota '%s' not found" % self.quota)
            elif num == 1:
                self.quota_guid = r['resources'][0]['metadata']['guid']
            else:
                self.module.fail_json(msg='Unexpected result getting quota guid. Expected 1, got %s.' % num)
        else:
            self.api_error(action, info)
 
    def create_org(self):
        action = "Create org '%s'" % self.name
        self.result['changed'] = True
        if not self.module.check_mode:
            parms = {'name': self.name, 'quota_definition_guid': self.quota_guid}
            url = '%s/v2/organizations' % (self.api_url)
            response, info = fetch_url(self.module, url, data=json.dumps(parms), headers=self.http_headers, method='POST')
            if info['status'] != 201:
                self.api_error(action, info)
        self.result['diff']['before'] = '<absent>\n'
        self.result['diff']['after']  = 'org %s quota %s\n' % (self.name, self.quota_guid)
        self.result['msg'].append(action)

    def delete_org(self):
        if self.name == 'system' and not self.force:
            self.module.fail_json(msg="Can't delete org 'system'")
        action = "Delete org '%s'" % self.name
        self.result['changed'] = True
        if not self.module.check_mode:
            url = '%s/v2/organizations/%s?async=false&recursive=true' % (self.api_url, self.org_guid)
            response, info = fetch_url(self.module, url, headers=self.http_headers, method='DELETE')
            if info['status'] != 204:
                self.api_error(action, info)
        self.result['diff']['before'] = 'org %s\n' % self.name
        self.result['diff']['after']  = '<absent>\n'
        self.result['msg'].append(action)

    def update_quota(self):
        action = "Update quota for org '%s' to '%s'" % (self.name, self.quota)
        self.result['changed'] = True
        if not self.module.check_mode:
            parms = {'quota_definition_guid': self.quota_guid}
            url = '%s/v2/organizations/%s' % (self.api_url, self.org_guid)
            response, info = fetch_url(self.module, url, data=json.dumps(parms), headers=self.http_headers, method='PUT')
            if info['status'] != 201:
                self.api_error(action, info)
        self.result['diff']['before'] = 'org %s quota %s\n' % (self.name, self.org_quota_guid)
        self.result['diff']['after']  = 'org %s quota %s\n' % (self.name, self.quota_guid)
        self.result['msg'].append(action)

    def api_error(self, action, info):
        if 'body' in info:
            try:
                body = json.loads(info['body'])
                description = error_description=body['error_description']
            except:
                description = body
        else:
            description = info
        self.module.fail_json(msg='Failed: %s' % action, status=info['status'], error_description=description)

def main():
    module = AnsibleModule(
        argument_spec       = dict(
            state           = dict(default='present', type='str', choices=['present', 'absent']),
            name            = dict(required=True, type='str', aliases=['id']),
            admin_user      = dict(required=True, type='str'),
            admin_password  = dict(required=True, type='str', no_log=True),
            domain          = dict(type='str'),
            protocol        = dict(default='https', type='str', choices=['http', 'https']),
            login_url       = dict(type='str'),
            api_url         = dict(type='str'),
            quota           = dict(default='default', type='str'),
            validate_certs  = dict(default=False, type='bool'),
            force           = dict(default=False, type='bool'),
        ),
        required_together = (
            ['api_url', 'login_url'],
            ),
        mutually_exclusive = (
            ['domain', 'login_url'],
            ['domain', 'api_url'],
            ),
        required_one_of = (
            ['id', 'name'],
            ),
        supports_check_mode = True,
    )    

    cf = CF_Org(module)

    state = module.params['state']
    if state == 'present':
        cf.present()
    elif state == 'absent':
        cf.absent()
    else:
        module.fail_json(msg='Invalid state: %s' % state)

    module.exit_json(**cf.result)

# Ansible boilerplate code
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()
