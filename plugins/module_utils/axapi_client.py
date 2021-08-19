# Copyright 2021, A10 Networks.
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


import errno
import json
import logging
import re
import requests
import socket
import sys
import time

from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as ae
from ansible_collections.a10.acos_axapi.plugins.module_utils import responses as acos_responses
from ansible_collections.a10.acos_axapi.plugins.module_utils import session

if sys.version_info >= (3, 0):
    import http.client as http_client
else:
    # Python 2
    import httplib as http_client


LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


def client_factory(host, port, protocol, username, password):
    http_client = HttpClient(host, port, protocol)
    sess = session.Session(http_client, username, password)
    return A10Client(sess)


class HttpClient(object):
    HEADERS = {
        "Content-type": "application/json",
        "User-Agent": "a10-ansible"
    }

    def __init__(self, host, port=None, protocol="https", timeout=None,
                 retry_errno_list=None):
        port = 80 if port is None and protocol == 'http' else 443
        self.url_base = "%s://%s:%s" % (protocol, host, port)

    def eval_resp(self, resp, method, api_url, headers):
        hdrs = self.HEADERS.copy()
        if headers:
            hdrs.update(headers)

        if 'response' in resp and 'status' in resp['response']:
            if resp['response']['status'] == 'fail':
                acos_responses.raise_axapi_ex(resp, method, api_url)

        if 'authorizationschema' in resp:
            acos_responses.raise_axapi_auth_error(
                resp, method, api_url, hdrs)

    def _merge_dicts(self, d1, d2):
        d = d1.copy()
        for k, v in d2.items():
            if k in d and isinstance(d[k], dict):
                d[k] = self._merge_dicts(d[k], d2[k])
            else:
                d[k] = d2[k]
        return d

    def request(self, method, api_url, params={}, headers=None,
                file_name=None, file_content=None, axapi_args=None, **kwargs):
        LOG.debug("axapi_http: full url = %s", self.url_base + api_url)
        LOG.debug("axapi_http: %s url = %s", method, api_url)

        # Update params with axapi_args for currently unsupported configuration of objects
        if axapi_args is not None:
            formatted_axapi_args = dict([(k.replace('_', '-'), v) for k, v in
                                         axapi_args.iteritems()])
            params = self._merge_dicts(params, formatted_axapi_args)

        if bool(file_name) != bool(file_content):
            raise ValueError("file_name and file_content must both be "
                             "populated if one is")

        files = None
        if file_name is not None:
            files = {
                'file': (file_name, file_content, "application/octet-stream"),
                'json': ('blob', payload, "application/json")
            }
            hdrs.pop("Content-type", None)
            hdrs.pop("Content-Type", None)

        hdrs = self.HEADERS.copy()
        if headers:
            hdrs.update(headers)

        payload = None
        if params and method != "GET":
            params_copy = params.copy()
            # Do not set encoding parameter if on python >= 3.x
            if sys.version_info >= (3, 0):
                payload = json.dumps(params_copy)
            else:
                payload = json.dumps(params_copy, encoding='utf-8')
            params = None

        try:
            resp = requests.request(method, self.url_base + api_url,
                                    verify=False, headers=hdrs, files=files,
                                    params=params, data=payload)
        except (socket.error, requests.exceptions.ConnectionError) as e:
            LOG.error("Connection to AXAPI could not be established")
            raise e

        return resp

    def get(self, api_url, params={}, headers=None, **kwargs):
        return self.request("GET", api_url, params, headers, **kwargs)

    def post(self, api_url, params={}, headers=None, **kwargs):
        return self.request("POST", api_url, params, headers, **kwargs)

    def put(self, api_url, params={}, headers=None, **kwargs):
        return self.request("PUT", api_url, params, headers, **kwargs)

    def delete(self, api_url, params={}, headers=None, **kwargs):
        return self.request("DELETE", api_url, params, headers, **kwargs)


class A10Client(object):

    def __init__(self, session):
        self.session = session

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
            resp = self.session.http_client.request(
                method, url, params, self.session.get_auth_header(),
                **kwargs)

            if params.get('commandList'):
                return self._parse_show_config_resp(resp.text)

            # Validate json response
            try:
                resp = resp.json()
            except ValueError as e:
                # The response is not JSON but it still succeeded.
                if resp.status_code in [200, 204]:
                    return resp.text
                else:
                    raise e
            self.session.http_client.eval_resp(
                resp, method, url, self.session.header)
        except Exception as e:
            self.session.close()
            raise e
        return resp

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
            self.post(url, payload)
        except Exception as ex:
            raise Exception("Could not activate due to: {0}".format(ex))

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
