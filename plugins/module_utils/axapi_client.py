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

from __future__ import absolute_import
from __future__ import unicode_literals

import json
import logging
import time

from requests.adapters import HTTPAdapter
from requests import Session

from ansible_collections.a10.acos_axapi.plugins.module_utils import responses as acos_responses
from ansible_collections.a10.acos_axapi.plugins.module_utils import logutils

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


class HttpClient(object):
    VERSION = "1.2.7"
    AXAPI_DEFAULT_REQ_TIMEOUT = 300
    HEADERS = {
        "Content-type": "application/json",
        "User-Agent": "A10-ACOS-AXAPI-AGENT-{}".format(VERSION),
    }

    def __init__(self, host, port=None, protocol="https", max_retries=3,
                 timeout=AXAPI_DEFAULT_REQ_TIMEOUT):
        if port is None:
            if protocol == 'http':
                self.port = 80
            else:
                self.port = 443
        else:
            self.port = port

        self.url_base = "%s://%s:%s" % (protocol, host, self.port)
        self.max_retries = max_retries
        self.timeout = timeout

    def _merge_dicts(self, d1, d2):
        d = d1.copy()
        # if isinstance(d1, dict) else {}
        for k, v in d2.items():
            if k in d and isinstance(d[k], dict):
                d[k] = self._merge_dicts(d[k], d2[k])
            else:
                d[k] = d2[k]
        return d

    def _dict_underscore_to_dash(self, my_dict):
        if type(my_dict) is list:
            item_list = []
            for item in my_dict:
                item_list.append(self._dict_underscore_to_dash(item))
            return item_list
        elif type(my_dict) is dict:
            item_dict = {}
            for k, v in my_dict.items():
                item_dict[k.replace('_', '-')] = self._dict_underscore_to_dash(v)
            return item_dict
        else:
            return my_dict

    def request_impl(self, method, api_url, params={}, headers=None,
                     file_name=None, file_content=None, axapi_args=None,
                     max_retries=None, timeout=None, **kwargs):
        LOG.debug("axapi_http: full url = %s", self.url_base + api_url)
        LOG.debug("axapi_http: %s url = %s", method, api_url)
        LOG.debug("axapi_http: params = %s", json.dumps(logutils.clean(params), indent=4))

        valid_http_codes = [200, 204]

        # Update params with axapi_args for currently unsupported configuration of objects
        if axapi_args is not None:
            formatted_axapi_args = self._dict_underscore_to_dash(axapi_args)
            params = self._merge_dicts(params, formatted_axapi_args)

        LOG.debug("axapi_http: params + axapi_args = %s", json.dumps(logutils.clean(params), indent=4))
        # Set data" variable for the request
        if params:
            params_copy = params.copy()
            LOG.debug("axapi_http: params_all = %s", logutils.clean(params_copy))
            payload = json.dumps(params_copy)
        else:
            payload = None

        if (file_name is None and file_content is not None) or \
           (file_name is not None and file_content is None):
            raise ValueError("file_name and file_content must both be populated if one is")

        if not max_retries:
            max_retries = self.max_retries
        if not timeout:
            timeout = self.timeout

        # Set "headers" variable for the request
        request_headers = self.HEADERS.copy()
        if headers:
            request_headers.update(headers)
        LOG.debug("axapi_http: headers = %s", json.dumps(logutils.clean(request_headers), indent=4))

        # Process files if passed as a parameter
        if file_name is not None:
            files = {
                'file': (file_name, file_content, "application/octet-stream"),
                'json': ('blob', payload, "application/json")
            }
            request_headers.pop("Content-type", None)
            request_headers.pop("Content-Type", None)

        # Create session to set HTTPAdapter or SSLAdapter and set max_retries
        session = Session()
        if self.port == 443:
            session.mount('https://', HTTPAdapter(max_retries=max_retries))
        else:
            session.mount('http://', HTTPAdapter(max_retries=max_retries))
        session_request = getattr(session, method.lower())

        # Make actual request and handle any errors
        try:
            if file_name is not None:
                device_response = session_request(
                    self.url_base + api_url, verify=False, files=files, headers=request_headers, timeout=timeout
                )
            else:
                device_response = session_request(
                    self.url_base + api_url, verify=False, data=payload, headers=request_headers, timeout=timeout
                )
        except (Exception) as e:
            LOG.error("acos_client failing with error %s after %s retries", e.__class__.__name__, max_retries)
            raise e
        finally:
            session.close()

        # Validate json response
        try:
            json_response = device_response.json()
            LOG.debug("axapi_http: data = %s", json.dumps(logutils.clean(json_response), indent=4))
        except ValueError as e:
            # The response is not JSON but it still succeeded.
            if device_response.status_code in valid_http_codes:
                return device_response.text, device_response.status_code
            else:
                raise e

        # Handle "fail" responses returned by AXAPI
        if 'response' in json_response and 'status' in json_response['response']:
            if json_response['response']['status'] == 'fail':
                    acos_responses.raise_axapi_ex(json_response, method, api_url)

        # Handle "authorizationschema" responses returned by AXAPI
        if 'authorizationschema' in json_response:
            acos_responses.raise_axapi_auth_error(json_response, method, api_url, headers)

        return json_response, device_response.status_code

    def request(self, method, api_url, params={}, headers=None,
                file_name=None, file_content=None, axapi_args=None,
                max_retries=None, timeout=None, **kwargs):
        retry_timeout = 300
        if timeout and timeout > retry_timeout:
            retry_timeout = timeout
        start_time = time.time()
        loop = True

        while loop:
            try:
                return self.request_impl(method, api_url, params, headers,
                                         file_name=file_name, file_content=file_content,
                                         max_retries=max_retries,
                                         timeout=timeout, axapi_args=axapi_args,
                                         **kwargs)

            except acos_responses.axapi_retry_exceptions() as e:
                LOG.warning("ACOS device system is busy: %s", str(e))
                loop = ((time.time() - start_time) <= retry_timeout)
                if not loop:
                    raise e
                time.sleep(1)
            except (Exception) as e:
                raise e

    def get(self, api_url, params={}, headers=None, max_retries=None, timeout=None, axapi_args=None, **kwargs):
        return self.request("GET", api_url, params, headers, max_retries=max_retries,
                            timeout=timeout, axapi_args=axapi_args, **kwargs)

    def post(self, api_url, params={}, headers=None, max_retries=None, timeout=None, axapi_args=None, **kwargs):
        return self.request("POST", api_url, params, headers, max_retries=max_retries,
                            timeout=timeout, axapi_args=axapi_args, **kwargs)

    def put(self, api_url, params={}, headers=None, max_retries=None, timeout=None, axapi_args=None, **kwargs):
        return self.request("PUT", api_url, params, headers, max_retries=max_retries,
                            timeout=timeout, axapi_args=axapi_args, **kwargs)

    def delete(self, api_url, params={}, headers=None, max_retries=None, timeout=None, axapi_args=None, **kwargs):
        return self.request("DELETE", api_url, params, headers, max_retries=max_retries,
                            timeout=timeout, axapi_args=axapi_args, **kwargs)
