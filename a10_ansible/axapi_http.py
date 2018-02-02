# Copyright 2014,  Doug Wiegley,  A10 Networks.
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


# TODO(mdurrant) - Organize these imports
import errno
import json
import logging
import requests
import socket
import sys
import time

from a10_ansible import errors as ae
from a10_ansible import responses as acos_responses

if sys.version_info >= (3, 0):
    import http.client as http_client
else:
    # Python 2
    import httplib as http_client



LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

broken_replies = {
    "": '{"response": {"status": "OK"}}'
}


class HttpClient(object):
    HEADERS = {
        "Content-type": "application/json",
        "User-Agent": "a10-ansible"
    }

    def __init__(self, host, port=None, protocol="https", timeout=None,
                 retry_errno_list=None):
        if port is None:
            if protocol is 'http':
                port = 80
            else:
                port = 443
        self.url_base = "%s://%s:%s" % (protocol, host, port)
        self.retry_errnos = []
        if retry_errno_list is not None:
            self.retry_errnos += retry_errno_list
        self.retry_err_strings = (['BadStatusLine'] +
                                  ['[Errno %s]' % n for n in self.retry_errnos] +
                                  [errno.errorcode[n] for n in self.retry_errnos
                                   if n in errno.errorcode])

    def request(self, method, api_url, params={}, headers=None,
                file_name=None, file_content=None, axapi_args=None, **kwargs):
        LOG.debug("axapi_http: full url = %s", self.url_base + api_url)
        LOG.debug("axapi_http: %s url = %s", method, api_url)
        # LOG.debug("axapi_http: params = %s", json.dumps(logutils.clean(params), indent=4))

        # Update params with axapi_args for currently unsupported configuration of objects
        if axapi_args is not None:
            formatted_axapi_args = dict([(k.replace('_', '-'), v) for k, v in
                                        axapi_args.iteritems()])
            params = self.merge_dicts(params, formatted_axapi_args)

        if (file_name is None and file_content is not None) or \
           (file_name is not None and file_content is None):
            raise ValueError("file_name and file_content must both be "
                             "populated if one is")

        hdrs = self.HEADERS.copy()
        if headers:
            hdrs.update(headers)

        if params:
            params_copy = params.copy()
            # params_copy.update(extra_params)
            # LOG.debug("axapi_http: params_all = %s", logutils.clean(params_copy))

            payload = json.dumps(params_copy, encoding='utf-8')
        else:
            payload = None

        # LOG.debug("axapi_http: headers = %s", json.dumps(logutils.clean(hdrs), indent=4))

        if file_name is not None:
            files = {
                'file': (file_name, file_content, "application/octet-stream"),
                'json': ('blob', payload, "application/json")
            }

            hdrs.pop("Content-type", None)
            hdrs.pop("Content-Type", None)

        last_e = None

        try:
            last_e = None
            if file_name is not None:
                z = requests.request(method, self.url_base + api_url, verify=False,
                                        files=files, headers=hdrs)
            else:
                z = requests.request(method, self.url_base + api_url, verify=False,
                                        data=payload, headers=hdrs)
        except (socket.error, requests.exceptions.ConnectionError) as e:
            # This needs to return an error response.
            raise e

        if z.status_code == 204:
            return None

        try:
            r = z.json()
        except ValueError as e:
            # The response is not JSON but it still succeeded.
            if z.status_code == 200:
                return {}
            else:
                raise e

        # LOG.debug("axapi_http: data = %s", json.dumps(logutils.clean(r), indent=4))

        if 'response' in r and 'status' in r['response']:
            if r['response']['status'] == 'fail':
                    acos_responses.raise_axapi_ex(r, method, api_url)

        if 'authorizationschema' in r:
            acos_responses.raise_axapi_auth_error(
                r, method, api_url, headers)

        return r

    def merge_dicts(self, d1, d2):
        d = d1.copy()
        # if isinstance(d1, dict) else {}
        for k, v in d2.items():
            if k in d and isinstance(d[k], dict):
                d[k] = self.merge_dicts(d[k], d2[k])
            else:
                d[k] = d2[k]
        return d


    def get(self, api_url, params={}, headers=None, **kwargs):
        return self.request("GET", api_url, params, headers, **kwargs)

    def post(self, api_url, params={}, headers=None, **kwargs):
        return self.request("POST", api_url, params, headers, **kwargs)

    def put(self, api_url, params={}, headers=None, **kwargs):
        return self.request("PUT", api_url, params, headers, **kwargs)

    def delete(self, api_url, params={}, headers=None, **kwargs):
        return self.request("DELETE", api_url, params, headers, **kwargs)


class Session(object):

    def __init__(self, http, username, password):
        self.http = http
        self.username = username
        self.password = password
        self.session_id = None

    @property
    def id(self):
        if self.session_id is None:
            self.authenticate(self.username, self.password)
        return self.session_id

    def get_auth_header(self):
        return {
            "Authorization": "A10 {0}".format(self.id)
        }

    def authenticate(self, username, password):
        url = "/axapi/v3/auth"
        payload = {
            'credentials': {
                "username": username,
                "password": password
            }
        }

        if self.session_id is not None:
            self.close()

        r = self.http.post(url, payload)
        if "authresponse" in r:
            self.session_id = str(r['authresponse']['signature'])
        else:
            self.session_id = None

        return r

    def close(self):
        # try:
        #     self.client.partition.active()
        # except Exception:
        #     pass
        if self.session_id is None:
            return

        try:
            h = {'Authorization': "A10 %s" % self.session_id}
            r = self.http.post('/axapi/v3/logoff', headers=h)
        finally:
            self.session_id = None

        return r

class A10Client(object):
    def __init__(self, session):
        self.session = session

    def _request(self, method, url, params, **kwargs):

        try:
            return self.session.http.request(method, url, params,
                                            self.session.get_auth_header(), **kwargs)
        except (ae.InvalidSessionID) as e:
                # try:
                #     p = self.client.current_partition
                #     self.client.session.close()
                #     self.client.partition.active(p)
                # except Exception:
                #     pass
                # return self._request(method, action, params, retry_count+1,
                #                      **kwargs)
            raise e

    def get(self, url, params={}, **kwargs):
        return self._request('GET', url, params, **kwargs)

    def post(self, url, params={}, **kwargs):
        return self._request('POST', url, params, **kwargs)

    def put(self, url, params={}, **kwargs):
        return self._request('PUT', url, params, **kwargs)

    def delete(self, url, params={}, **kwargs):
        return self._request('DELETE', url, params, **kwargs)

def http_factory(host, port, protocol):
    return HttpClient(host, port, protocol)

def session_factory(http, username, password):
    return Session(http, username, password)

def client_factory(host, port, protocol, username, password):
    http_cli = http_factory(host, port, protocol)
    session = session_factory(http_cli, username, password)
    return A10Client(session)
