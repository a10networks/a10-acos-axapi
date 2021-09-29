# Copyright 2021,  A10 Networks.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re
import json

from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as ae
from ansible_collections.a10.acos_axapi.plugins.module_utils import axapi_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import auth


def client_factory(host, port, protocol, username, password):
    http_client = axapi_client.HttpClient(host, port, protocol)
    auth_sess = auth.ClientAuth(http_client, username, password)
    return A10Client(auth_sess, http_client)


class A10Client(object):

    def __init__(self, auth_session, http_client):
        self.auth_session = auth_session
        self.http_client = http_client

    def _parse_show_config_resp(self, resp_text):
        urls = []
        config_vals = []
        config = {}

        resp_list = resp_text.split('\r')
        if len(resp_list) > 1:
            resp_text = resp_list[-1]

        resp_text = resp_text.replace('\n', ' ')[:-5]
        pattern = '(a10-url:)([A-Za-z\/1-9\-])+'
        reg_match = re.search(pattern, resp_text)

        while reg_match != None:
            reg_found = reg_match.group(0)
            resp_text = resp_text.replace(reg_found, '')

            if pattern == '(a10-url:)([A-Za-z\/1-9\-])+':
                urls.append(reg_found)
                pattern = '(?:(?!a10-url).)+'
            else:
                config_vals.append(json.loads(reg_found))
                pattern = '(a10-url:)([A-Za-z\/1-9\-])+'

            reg_match = re.search(pattern, resp_text)

        for i in range(0, len(urls)):
            temp_url = urls[i].replace('a10-url:', '')
            config[temp_url] = config_vals[i]
        return config

    def _request(self, method, url, params, **kwargs):
        try:
            resp, status_code = self.http_client.request(
                method, url, params, self.auth_session.get_auth_header(),
                **kwargs)

            if params.get('commandList'):
                return self._parse_show_config_resp(resp.text)
        except Exception as e:
            self.auth_session.close()
            raise e
        return resp, status_code

    def activate_partition(self, partition):
        url = "/axapi/v3/active-partition"
        shared = "true" if partition == "shared" else "false"
        payload = {
            "active-partition": {
                "curr_part_name": partition,
                "shared": shared
            }
        }
        try:
            resp, status_code = self.post(url, payload)
        except Exception as ex:
            raise Exception("Could not activate partition due to: {0}".format(ex))

        if status_code == 204:
            raise Exception("Partition {} does not exist".format(partition))

    def switch_device_context(self, device_context_id):
        url = "/axapi/v3/device-context"
        payload = {
            "device-context": {
                "device-id": device_context_id
            }
        }
        try:
            self.post(url, payload)
        except Exception as ex:
            raise Exception("Could not switch device context due to: {0}".format(ex))

    def get(self, url, params={}, **kwargs):
        return self._request('GET', url, params, **kwargs)

    def post(self, url, params={}, **kwargs):
        return self._request('POST', url, params, **kwargs)

    def put(self, url, params={}, **kwargs):
        return self._request('PUT', url, params, **kwargs)

    def delete(self, url, params={}, **kwargs):
        return self._request('DELETE', url, params, **kwargs)