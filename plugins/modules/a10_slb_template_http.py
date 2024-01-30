#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_http
description:
    - HTTP
author: A10 Networks
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    name:
        description:
        - "HTTP Template Name"
        type: str
        required: True
    compression_auto_disable_on_high_cpu:
        description:
        - "Auto-disable software compression on high cpu usage (Disable compression if cpu
          usage is above threshold. Default is off.)"
        type: int
        required: False
    compression_content_type:
        description:
        - "Field compression_content_type"
        type: list
        required: False
        suboptions:
            content_type:
                description:
                - "Compression content-type"
                type: str
    compression_enable:
        description:
        - "Enable Compression"
        type: bool
        required: False
    compression_exclude_content_type:
        description:
        - "Field compression_exclude_content_type"
        type: list
        required: False
        suboptions:
            exclude_content_type:
                description:
                - "Compression exclude content-type (Compression exclude content type)"
                type: str
    compression_exclude_uri:
        description:
        - "Field compression_exclude_uri"
        type: list
        required: False
        suboptions:
            exclude_uri:
                description:
                - "Compression exclude uri"
                type: str
    compression_keep_accept_encoding:
        description:
        - "Keep accept encoding"
        type: bool
        required: False
    compression_keep_accept_encoding_enable:
        description:
        - "Enable Server Accept Encoding"
        type: bool
        required: False
    compression_level:
        description:
        - "compression level, default 1 (compression level value, default is 1)"
        type: int
        required: False
    compression_minimum_content_length:
        description:
        - "Minimum Content Length (Minimum content length for compression in bytes.
          Default is 120.)"
        type: int
        required: False
    default_charset:
        description:
        - "'iso-8859-1'= Use ISO-8859-1 as the default charset; 'utf-8'= Use UTF-8 as the
          default charset; 'us-ascii'= Use US-ASCII as the default charset;"
        type: str
        required: False
    max_concurrent_streams:
        description:
        - "(http2 only) Max concurrent streams, default 50"
        type: int
        required: False
    max_transaction_allowed:
        description:
        - "Max transactions allowed, default 0 (no limit)"
        type: int
        required: False
    stream_cancellation_limit:
        description:
        - "cancellation limit, default 0 (accumulated cancellation limit value, default is
          0)"
        type: int
        required: False
    stream_cancellation_rate:
        description:
        - "cancellation rate, default 10 (cancellation rate value, default is 10)"
        type: int
        required: False
    frame_limit:
        description:
        - "Limit the number of CONTINUATION, PING, PRIORITY, RESET, SETTINGS and empty
          frames in one HTTP2 connection, default 10000"
        type: int
        required: False
    failover_url:
        description:
        - "Failover to this URL (Failover URL Name)"
        type: str
        required: False
    host_switching:
        description:
        - "Field host_switching"
        type: list
        required: False
        suboptions:
            host_switching_type:
                description:
                - "'contains'= Select service group if hostname contains another string; 'ends-
          with'= Select service group if hostname ends with another string; 'equals'=
          Select service group if hostname equals another string; 'starts-with'= Select
          service group if hostname starts with another string; 'regex-match'= Select
          service group if URL string matches with regular expression; 'host-hits-
          enable'= Enables Host Hits counters;"
                type: str
            host_match_string:
                description:
                - "Hostname String"
                type: str
            host_service_group:
                description:
                - "Create a Service Group comprising Servers (Service Group Name)"
                type: str
    insert_client_ip:
        description:
        - "Insert Client IP address into HTTP header"
        type: bool
        required: False
    insert_client_ip_header_name:
        description:
        - "HTTP Header Name for inserting Client IP"
        type: str
        required: False
    client_ip_hdr_replace:
        description:
        - "Replace the existing header"
        type: bool
        required: False
    insert_client_port:
        description:
        - "Insert Client Port address into HTTP header"
        type: bool
        required: False
    insert_client_port_header_name:
        description:
        - "HTTP Header Name for inserting Client Port"
        type: str
        required: False
    client_port_hdr_replace:
        description:
        - "Replace the existing header"
        type: bool
        required: False
    log_retry:
        description:
        - "log when HTTP request retry"
        type: bool
        required: False
    non_http_bypass:
        description:
        - "Bypass non-http traffic instead of dropping"
        type: bool
        required: False
    bypass_sg:
        description:
        - "Select service group for non-http traffic (Service Group Name)"
        type: str
        required: False
    redirect:
        description:
        - "Automatically send a redirect response"
        type: bool
        required: False
    rd_simple_loc:
        description:
        - "Redirect location tag absolute URI string"
        type: str
        required: False
    rd_secure:
        description:
        - "Use HTTPS"
        type: bool
        required: False
    rd_port:
        description:
        - "Port (Port Number)"
        type: int
        required: False
    rd_resp_code:
        description:
        - "'301'= Moved Permanently; '302'= Found; '303'= See Other; '307'= Temporary
          Redirect;"
        type: str
        required: False
    redirect_rewrite:
        description:
        - "Field redirect_rewrite"
        type: dict
        required: False
        suboptions:
            match_list:
                description:
                - "Field match_list"
                type: list
            redirect_secure:
                description:
                - "Use HTTPS"
                type: bool
            redirect_secure_port:
                description:
                - "Port (Port Number)"
                type: int
    request_header_erase_list:
        description:
        - "Field request_header_erase_list"
        type: list
        required: False
        suboptions:
            request_header_erase:
                description:
                - "Erase a header from HTTP request (Header Name)"
                type: str
    request_header_insert_list:
        description:
        - "Field request_header_insert_list"
        type: list
        required: False
        suboptions:
            request_header_insert:
                description:
                - "Insert a header into HTTP request (Header Content (Format= '[name]=[value]'))"
                type: str
            request_header_insert_type:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    response_content_replace_list:
        description:
        - "Field response_content_replace_list"
        type: list
        required: False
        suboptions:
            response_content_replace:
                description:
                - "replace the data from HTTP response content (String in the http content need to
          be replaced)"
                type: str
            response_new_string:
                description:
                - "String will be in the http content"
                type: str
    response_header_erase_list:
        description:
        - "Field response_header_erase_list"
        type: list
        required: False
        suboptions:
            response_header_erase:
                description:
                - "Erase a header from HTTP response (Header Name)"
                type: str
    response_header_insert_list:
        description:
        - "Field response_header_insert_list"
        type: list
        required: False
        suboptions:
            response_header_insert:
                description:
                - "Insert a header into HTTP response (Header Content (Format= '[name]=[value]'))"
                type: str
            response_header_insert_type:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    request_timeout:
        description:
        - "Request timeout if response not received (timeout in seconds)"
        type: int
        required: False
    retry_on_5xx:
        description:
        - "Retry http request on HTTP 5xx code and request timeout"
        type: bool
        required: False
    retry_on_5xx_val:
        description:
        - "Number of times to retry (default is 3)"
        type: int
        required: False
    retry_on_5xx_per_req:
        description:
        - "Retry http request on HTTP 5xx code for each request"
        type: bool
        required: False
    retry_on_5xx_per_req_val:
        description:
        - "Number of times to retry (default is 3)"
        type: int
        required: False
    strict_transaction_switch:
        description:
        - "Force server selection on every HTTP request"
        type: bool
        required: False
    template:
        description:
        - "Field template"
        type: dict
        required: False
        suboptions:
            logging:
                description:
                - "Logging template (Logging Config name)"
                type: str
    term_11client_hdr_conn_close:
        description:
        - "Terminate HTTP 1.1 client when req has Connection= close"
        type: bool
        required: False
    persist_on_401:
        description:
        - "Persist to the same server if the response code is 401"
        type: bool
        required: False
    http_100_cont_wait_for_req_complete:
        description:
        - "When REQ has Expect 100 and response is not 100, then wait for whole request to
          be sent"
        type: bool
        required: False
    url_hash_persist:
        description:
        - "Use URL's hash value to select server"
        type: bool
        required: False
    url_hash_offset:
        description:
        - "Skip part of URL to calculate hash value (Offset of the URL string)"
        type: int
        required: False
    url_hash_first:
        description:
        - "Use the begining part of URL to calculate hash value (URL string length to
          calculate hash value)"
        type: int
        required: False
    url_hash_last:
        description:
        - "Use the end part of URL to calculate hash value (URL string length to calculate
          hash value)"
        type: int
        required: False
    use_server_status:
        description:
        - "Use Server-Status header to do URL hashing"
        type: bool
        required: False
    url_switching:
        description:
        - "Field url_switching"
        type: list
        required: False
        suboptions:
            url_switching_type:
                description:
                - "'contains'= Select service group if URL string contains another string; 'ends-
          with'= Select service group if URL string ends with another string; 'equals'=
          Select service group if URL string equals another string; 'starts-with'= Select
          service group if URL string starts with another string; 'regex-match'= Select
          service group if URL string matches with regular expression; 'url-case-
          insensitive'= Case insensitive URL switching; 'url-hits-enable'= Enables URL
          Hits;"
                type: str
            url_match_string:
                description:
                - "URL String"
                type: str
            url_service_group:
                description:
                - "Create a Service Group comprising Servers (Service Group Name)"
                type: str
    req_hdr_wait_time:
        description:
        - "HTTP request header wait time before abort connection"
        type: bool
        required: False
    req_hdr_wait_time_val:
        description:
        - "Number of seconds wait for client request header (default is 7)"
        type: int
        required: False
    request_line_case_insensitive:
        description:
        - "Parse http request line as case insensitive"
        type: bool
        required: False
    keep_client_alive:
        description:
        - "Keep client alive"
        type: bool
        required: False
    cookie_format:
        description:
        - "'rfc6265'= Follow rfc6265;"
        type: str
        required: False
    prefix:
        description:
        - "'host'= the cookie will have been set with a Secure attribute, a Path attribute
          with a value of /, and no Domain attribute; 'secure'= the cookie will have been
          set with a Secure attribute; 'check'= check server prefix and enforce prefix
          format;"
        type: str
        required: False
    cookie_samesite:
        description:
        - "'none'= none; 'lax'= lax; 'strict'= strict;"
        type: str
        required: False
    server_support_http2_only:
        description:
        - "Notify the vport regarding whether server supports http2 only"
        type: bool
        required: False
    server_support_http2_only_value:
        description:
        - "'auto-detect'= Commuincate with the server via HTTP/2 when an support-
          http2-only rport is detected; 'force'= Communicate with the server via HTTP/2
          when possible;"
        type: str
        required: False
    client_idle_timeout:
        description:
        - "Client session timeout if the next request is not received (timeout in seconds.
          0 means disable, default is 0)"
        type: int
        required: False
    disallowed_methods:
        description:
        - "Enable disallowed-method check (List of disallowed HTTP methods)"
        type: str
        required: False
    disallowed_methods_action:
        description:
        - "'drop'= Respond 400 directly;"
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False
    http_protocol_check:
        description:
        - "Field http_protocol_check"
        type: dict
        required: False
        suboptions:
            h2up_content_length_alias:
                description:
                - "'drop'= Drop the request and send 400 to the client side;"
                type: str
            malformed_h2up_header_value:
                description:
                - "'drop'= Drop the request and send 400 to the client side;"
                type: str
            malformed_h2up_scheme_value:
                description:
                - "'drop'= Drop the request and send 400 to the client side;"
                type: str
            h2up_with_transfer_encoding:
                description:
                - "'drop'= Drop the request and send 400 to the client side;"
                type: str
            multiple_content_length:
                description:
                - "'drop'= Drop the request and send 400 to the client side;"
                type: str
            multiple_transfer_encoding:
                description:
                - "'drop'= Drop the request and send 400 to the client side;"
                type: str
            transfer_encoding_and_content_length:
                description:
                - "'drop'= Drop the request and Send 400 to the client side;"
                type: str
            get_and_payload:
                description:
                - "'drop'= Drop the request and send 400 to the client side;"
                type: str
            h2up_with_host_and_auth:
                description:
                - "'drop'= Drop the request and send 400 to the client side;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            header_filter_rule_list:
                description:
                - "Field header_filter_rule_list"
                type: list

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "http_100_cont_wait_for_req_complete", "bypass_sg", "client_idle_timeout", "client_ip_hdr_replace", "client_port_hdr_replace", "compression_auto_disable_on_high_cpu", "compression_content_type", "compression_enable", "compression_exclude_content_type", "compression_exclude_uri", "compression_keep_accept_encoding",
    "compression_keep_accept_encoding_enable", "compression_level", "compression_minimum_content_length", "cookie_format", "cookie_samesite", "default_charset", "disallowed_methods", "disallowed_methods_action", "failover_url", "frame_limit", "host_switching", "http_protocol_check", "insert_client_ip", "insert_client_ip_header_name",
    "insert_client_port", "insert_client_port_header_name", "keep_client_alive", "log_retry", "max_concurrent_streams", "max_transaction_allowed", "name", "non_http_bypass", "persist_on_401", "prefix", "rd_port", "rd_resp_code", "rd_secure", "rd_simple_loc", "redirect", "redirect_rewrite", "req_hdr_wait_time", "req_hdr_wait_time_val",
    "request_header_erase_list", "request_header_insert_list", "request_line_case_insensitive", "request_timeout", "response_content_replace_list", "response_header_erase_list", "response_header_insert_list", "retry_on_5xx", "retry_on_5xx_per_req", "retry_on_5xx_per_req_val", "retry_on_5xx_val", "server_support_http2_only",
    "server_support_http2_only_value", "stream_cancellation_limit", "stream_cancellation_rate", "strict_transaction_switch", "template", "term_11client_hdr_conn_close", "url_hash_first", "url_hash_last", "url_hash_offset", "url_hash_persist", "url_switching", "use_server_status", "user_tag", "uuid",
    ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'name': {
            'type': 'str',
            'required': True,
            },
        'compression_auto_disable_on_high_cpu': {
            'type': 'int',
            },
        'compression_content_type': {
            'type': 'list',
            'content_type': {
                'type': 'str',
                }
            },
        'compression_enable': {
            'type': 'bool',
            },
        'compression_exclude_content_type': {
            'type': 'list',
            'exclude_content_type': {
                'type': 'str',
                }
            },
        'compression_exclude_uri': {
            'type': 'list',
            'exclude_uri': {
                'type': 'str',
                }
            },
        'compression_keep_accept_encoding': {
            'type': 'bool',
            },
        'compression_keep_accept_encoding_enable': {
            'type': 'bool',
            },
        'compression_level': {
            'type': 'int',
            },
        'compression_minimum_content_length': {
            'type': 'int',
            },
        'default_charset': {
            'type': 'str',
            'choices': ['iso-8859-1', 'utf-8', 'us-ascii']
            },
        'max_concurrent_streams': {
            'type': 'int',
            },
        'max_transaction_allowed': {
            'type': 'int',
            },
        'stream_cancellation_limit': {
            'type': 'int',
            },
        'stream_cancellation_rate': {
            'type': 'int',
            },
        'frame_limit': {
            'type': 'int',
            },
        'failover_url': {
            'type': 'str',
            },
        'host_switching': {
            'type': 'list',
            'host_switching_type': {
                'type': 'str',
                'choices': ['contains', 'ends-with', 'equals', 'starts-with', 'regex-match', 'host-hits-enable']
                },
            'host_match_string': {
                'type': 'str',
                },
            'host_service_group': {
                'type': 'str',
                }
            },
        'insert_client_ip': {
            'type': 'bool',
            },
        'insert_client_ip_header_name': {
            'type': 'str',
            },
        'client_ip_hdr_replace': {
            'type': 'bool',
            },
        'insert_client_port': {
            'type': 'bool',
            },
        'insert_client_port_header_name': {
            'type': 'str',
            },
        'client_port_hdr_replace': {
            'type': 'bool',
            },
        'log_retry': {
            'type': 'bool',
            },
        'non_http_bypass': {
            'type': 'bool',
            },
        'bypass_sg': {
            'type': 'str',
            },
        'redirect': {
            'type': 'bool',
            },
        'rd_simple_loc': {
            'type': 'str',
            },
        'rd_secure': {
            'type': 'bool',
            },
        'rd_port': {
            'type': 'int',
            },
        'rd_resp_code': {
            'type': 'str',
            'choices': ['301', '302', '303', '307']
            },
        'redirect_rewrite': {
            'type': 'dict',
            'match_list': {
                'type': 'list',
                'redirect_match': {
                    'type': 'str',
                    },
                'rewrite_to': {
                    'type': 'str',
                    }
                },
            'redirect_secure': {
                'type': 'bool',
                },
            'redirect_secure_port': {
                'type': 'int',
                }
            },
        'request_header_erase_list': {
            'type': 'list',
            'request_header_erase': {
                'type': 'str',
                }
            },
        'request_header_insert_list': {
            'type': 'list',
            'request_header_insert': {
                'type': 'str',
                },
            'request_header_insert_type': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
                }
            },
        'response_content_replace_list': {
            'type': 'list',
            'response_content_replace': {
                'type': 'str',
                },
            'response_new_string': {
                'type': 'str',
                }
            },
        'response_header_erase_list': {
            'type': 'list',
            'response_header_erase': {
                'type': 'str',
                }
            },
        'response_header_insert_list': {
            'type': 'list',
            'response_header_insert': {
                'type': 'str',
                },
            'response_header_insert_type': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
                }
            },
        'request_timeout': {
            'type': 'int',
            },
        'retry_on_5xx': {
            'type': 'bool',
            },
        'retry_on_5xx_val': {
            'type': 'int',
            },
        'retry_on_5xx_per_req': {
            'type': 'bool',
            },
        'retry_on_5xx_per_req_val': {
            'type': 'int',
            },
        'strict_transaction_switch': {
            'type': 'bool',
            },
        'template': {
            'type': 'dict',
            'logging': {
                'type': 'str',
                }
            },
        'term_11client_hdr_conn_close': {
            'type': 'bool',
            },
        'persist_on_401': {
            'type': 'bool',
            },
        'http_100_cont_wait_for_req_complete': {
            'type': 'bool',
            },
        'url_hash_persist': {
            'type': 'bool',
            },
        'url_hash_offset': {
            'type': 'int',
            },
        'url_hash_first': {
            'type': 'int',
            },
        'url_hash_last': {
            'type': 'int',
            },
        'use_server_status': {
            'type': 'bool',
            },
        'url_switching': {
            'type': 'list',
            'url_switching_type': {
                'type': 'str',
                'choices': ['contains', 'ends-with', 'equals', 'starts-with', 'regex-match', 'url-case-insensitive', 'url-hits-enable']
                },
            'url_match_string': {
                'type': 'str',
                },
            'url_service_group': {
                'type': 'str',
                }
            },
        'req_hdr_wait_time': {
            'type': 'bool',
            },
        'req_hdr_wait_time_val': {
            'type': 'int',
            },
        'request_line_case_insensitive': {
            'type': 'bool',
            },
        'keep_client_alive': {
            'type': 'bool',
            },
        'cookie_format': {
            'type': 'str',
            'choices': ['rfc6265']
            },
        'prefix': {
            'type': 'str',
            'choices': ['host', 'secure', 'check']
            },
        'cookie_samesite': {
            'type': 'str',
            'choices': ['none', 'lax', 'strict']
            },
        'server_support_http2_only': {
            'type': 'bool',
            },
        'server_support_http2_only_value': {
            'type': 'str',
            'choices': ['auto-detect', 'force']
            },
        'client_idle_timeout': {
            'type': 'int',
            },
        'disallowed_methods': {
            'type': 'str',
            },
        'disallowed_methods_action': {
            'type': 'str',
            'choices': ['drop']
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'http_protocol_check': {
            'type': 'dict',
            'h2up_content_length_alias': {
                'type': 'str',
                'choices': ['drop']
                },
            'malformed_h2up_header_value': {
                'type': 'str',
                'choices': ['drop']
                },
            'malformed_h2up_scheme_value': {
                'type': 'str',
                'choices': ['drop']
                },
            'h2up_with_transfer_encoding': {
                'type': 'str',
                'choices': ['drop']
                },
            'multiple_content_length': {
                'type': 'str',
                'choices': ['drop']
                },
            'multiple_transfer_encoding': {
                'type': 'str',
                'choices': ['drop']
                },
            'transfer_encoding_and_content_length': {
                'type': 'str',
                'choices': ['drop']
                },
            'get_and_payload': {
                'type': 'str',
                'choices': ['drop']
                },
            'h2up_with_host_and_auth': {
                'type': 'str',
                'choices': ['drop']
                },
            'uuid': {
                'type': 'str',
                },
            'header_filter_rule_list': {
                'type': 'list',
                'seq_num': {
                    'type': 'int',
                    'required': True,
                    },
                'match_type_value': {
                    'type': 'str',
                    'choices': ['full-text', 'pcre']
                    },
                'header_name_value': {
                    'type': 'str',
                    },
                'header_value_value': {
                    'type': 'str',
                    },
                'action_value': {
                    'type': 'str',
                    'choices': ['drop']
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/http/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/http"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["http"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["http"].get(k) != v:
            change_results["changed"] = True
            config_changes["http"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("http", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["http"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["http-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
