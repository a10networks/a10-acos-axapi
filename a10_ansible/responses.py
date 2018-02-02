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

import re

from a10_ansible import errors as ae

RESPONSE_CODES = {
    33619969: {
        '*': {
            '*': ae.InUse
        }
    },
    67371011: {
        '*': {
            '*': ae.Exists
        }
    },
    419495936: {
        '*': {
            '/axapi/v3/logoff': None,
            '*': ae.InvalidSessionID
        }
    },
    520749062: {
        '*': {
            '*': ae.NotFound
        }
    },
    654311495: {
        '*': {
            '*': ae.Exists
        }
    },
    67240011: {
        '*': {
            '*': ae.Exists
        }
    },
    754974732: {
        '*': {
            '*': ae.Exists
        }
    },
    754974733: {
        '*': {
            '*': ae.PartitionIdExists
        }
    },
    1023410176: {
        'DELETE': {
            '*': None
        },
        '*': {
            '*': ae.NotFound
        }
    },
    1023410181: {
        'DELETE': {
            '*': None
        },
        '*': {
            '/axapi/v3/slb/service-group/.*/member/': ae.NotFound,
            '*': ae.NotFound
        }
    },
    1023410183: {
        '*': {
            '*': ae.Exists
        }
    },
    1023451145: {
        '*': {
            '*': ae.Exists
        }
    },
    1023459339: {
        '*': {
            '/axapi/v3/slb/server': ae.Exists
        }
    },
    1023459393: {
        '*': {
            '*': ae.InvalidParameter
        }
    },
    1023459335: {
        '*': {
            '*': ae.Exists
        }
    },
    1023460352: {
        'DELETE': {
            '*': None
        },
        '*': {
            '*': ae.NotFound
        }
    },
    1023463424: {
        '*': {
            '*': ae.ConfigManagerNotReady
        }
    },
    1023475722: {
        '*': {
            '*': ae.NotFound
        }
    },
    1023508480: {
        '*': {
            '*': ae.AxapiJsonFormatError
        }
    },
    1023509504: {
        '*': {
            '*': ae.NotFound
        }
    },
    1023524874: {
        '*': {
            '*': ae.AxapiJsonFormatError
        }
    },
    1023656960: {
        '*': {
            '*': ae.NotFound
        }
    },
    1023656962: {
        '*': {
            '*': ae.NotFound
        }
    },
    1207960052: {
        '*': {
            '/axapi/v3/logoff': None,
            '*': ae.InvalidSessionID
        }
    },
    1207959957: {
        '*': {
            '*': ae.NotFound
        }
    },
    1208025092: {
        '*': {
            '/axapi/v3/logoff': None,
            '*': ae.InvalidSessionID
        }
    },
    1208025095: {
        '*': {
            '*': ae.ConfigManagerNotReady
        }
    },
    1023443968: {
        'DELETE': {
            '*': None
        },
        '*': {
            '*': ae.NotFound
        }
    },
    1023451144: {
        '*': {
            '*': ae.Exists
        }
    },
    1023475727: {
        '*': {
            '*': ae.NotFound
        }
    },
    4294967295: {
        '*': {
            '*': ae.ConfigManagerNotReady
        }
    },
}


def raise_axapi_auth_error(response, method, api_url, headers):
    if 'authorizationschema' in response:
        code = response['authorizationschema']['code']
        s = response['authorizationschema']['error']
        if code == 401:
            if headers and 'Authorization' in headers:
                raise ae.InvalidSessionID(code, s)
            else:
                raise ae.AuthenticationFailure(code, s)
        elif code == 403:
            raise ae.AuthenticationFailure(code, s)


def raise_axapi_ex(response, method, api_url):
    if 'response' in response and 'err' in response['response']:
        code = response['response']['err']['code']

        # Check if this is a known error code that we want to map.
        if code in RESPONSE_CODES:
            ex_dict = RESPONSE_CODES[code]
            ex = None

            # Now match against specific HTTP method exceptions
            if method in ex_dict:
                x = ex_dict[method]
            else:
                x = ex_dict['*']

            # Now try to find specific API method exceptions
            matched = False
            for k in x.keys():
                if k != '*' and re.match('^'+k, api_url):
                    matched = True
                    ex = x[k]

            # If we get here, try for a fallback exception for this code
            if not matched and not ex and '*' in x:
                ex = x['*']

            # Alright, time to actually do something
            if ex:
                raise ex(code, response['response']['err']['msg'])
            else:
                return

        raise ae.ACOSException(code, response['response']['err']['msg'])

    raise ae.ACOSException()
