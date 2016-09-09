#!/usr/bin/python

import sys
import os
import json
import urllib

DOCUMENTATION = '''
---
'''

EXAMPLES = '''
#
'''

class CF_Auth(object):
    def __init__(self, module):
        self.changed      = False
        self.exists       = False
        self.msg          = []
        self.http_headers = {}

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
            self.msg.append('*** Running in check mode ***')

        self.login()
        self.get_org()

    def present(self):
        self.get_quota_guid()
        if self.exists:
            self.msg.append("Org '%s' already exists" % self.name)
            if self.org_quota_guid != self.quota_guid:
                self.update_quota()
        else:
            self.create_org()

    def absent(self):
        if self.exists:
            self.delete_org()
        else:
            self.msg.append("Org '%s' doesn't exist" % self.name)

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
        self.changed = True
        if not self.module.check_mode:
            parms = {'name': self.name, 'quota_definition_guid': self.quota_guid}
            url = '%s/v2/organizations' % (self.api_url)
            response, info = fetch_url(self.module, url, data=json.dumps(parms), headers=self.http_headers, method='POST')
            if info['status'] != 201:
                self.api_error(action, info)
        self.msg.append(action)

    def delete_org(self):
        if self.name == 'system' and not self.force:
            self.module.fail_json(msg="Can't delete org 'system'")
        action = "Delete org '%s'" % self.name
        self.changed = True
        if not self.module.check_mode:
            url = '%s/v2/organizations/%s?async=false&recursive=true' % (self.api_url, self.org_guid)
            response, info = fetch_url(self.module, url, headers=self.http_headers, method='DELETE')
            if info['status'] != 204:
                self.api_error(action, info)
        self.msg.append(action)

    def update_quota(self):
        action = "Update quota for org '%s' to '%s'" % (self.name, self.quota)
        self.changed = True
        if not self.module.check_mode:
            parms = {'quota_definition_guid': self.quota_guid}
            url = '%s/v2/organizations/%s' % (self.api_url, self.org_guid)
            response, info = fetch_url(self.module, url, data=json.dumps(parms), headers=self.http_headers, method='PUT')
            if info['status'] != 201:
                self.api_error(action, info)
        self.msg.append(action)

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
            state           = dict(required=True, type='str', choices=['present', 'absent']),
            name            = dict(required=True, type='str', aliases=['id']),
            admin_user      = dict(required=True, type='str'),
            admin_password  = dict(required=True, type='str'),
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

    cf = CF_Auth(module)

    state = module.params['state']
    if state == 'present':
        cf.present()
    elif state == 'absent':
        cf.absent()
    else:
        module.fail_json(msg='Invalid state: %s' % state)

    module.exit_json(changed=cf.changed, msg=', '.join(cf.msg))

# Ansible boilerplate code
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()
