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


class Session(object):

    def __init__(self, http_client, username, password):
        self.http_client = http_client
        self.username = username
        self.password = password
        self.session_id = None
        self.header = None

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
            "credentials": {
                "username": username,
                "password": password
            }
        }

        if self.session_id is not None:
            self.close()

        resp = self.http_client.post(url, payload)
        # Validate json response
        try:
            resp = resp.json()
        except ValueError as e:
            # The response is not JSON but it still succeeded.
            if resp.status_code in [200, 204]:
                return resp.text
            else:
                raise e
        self.http_client.eval_resp(resp, 'POST', url, self.header)

        if "authresponse" in resp:
            self.session_id = str(resp['authresponse']['signature'])
        else:
            self.session_id = None
        return resp

    def close(self):
        if self.session_id is None:
            return
        self.header = {
            'Authorization': "A10 %s" % self.session_id
        }
        self.session_id = None
        url = '/axapi/v3/logoff'
        resp = self.http_client.post(url, headers=self.header)

        # Validate json response
        try:
            resp = resp.json()
        except ValueError as e:
            # The response is not JSON but it still succeeded.
            if resp.status_code in [200, 204]:
                return resp.text
            else:
                raise e

        self.http_client.eval_resp(resp, 'POST', url, self.header)
        return resp