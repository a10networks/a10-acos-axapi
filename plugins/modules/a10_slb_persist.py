#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_persist
description:
    - Configure persist
author: A10 Networks 2021
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hash_tbl_trylock_fail'= Hash tbl lock fail; 'hash_tbl_create_ok'=
          Hash tbl create ok; 'hash_tbl_create_fail'= Hash tbl create fail;
          'hash_tbl_free'= Hash tbl free; 'hash_tbl_rst_updown'= Hash tbl reset
          (up/down); 'hash_tbl_rst_adddel'= Hash tbl reset (add/del); 'url_hash_pri'= URL
          hash persist (pri); 'url_hash_enqueue'= URL hash persist (enQ); 'url_hash_sec'=
          URL hash persist (sec); 'url_hash_fail'= URL hash persist fail;
          'header_hash_pri'= Header hash persist(pri); 'header_hash_enqueue'= Header hash
          persist(enQ); 'header_hash_sec'= Header hash persist(sec); 'header_hash_fail'=
          Header hash persist fail; 'src_ip'= SRC IP persist ok; 'src_ip_enqueue'= SRC IP
          persist enqueue; 'src_ip_fail'= SRC IP persist fail; 'src_ip_new_sess_cache'=
          SRC IP new sess (cache); 'src_ip_new_sess_cache_fail'= SRC IP new sess fail
          (c); 'src_ip_new_sess_sel'= SRC IP new sess (select);
          'src_ip_new_sess_sel_fail'= SRC IP new sess fail (s); 'src_ip_hash_pri'= SRC IP
          hash persist(pri); 'src_ip_hash_enqueue'= SRC IP hash persist(enQ);
          'src_ip_hash_sec'= SRC IP hash persist(sec); 'src_ip_hash_fail'= SRC IP hash
          persist fail; 'src_ip_enforce'= Enforce higher priority; 'dst_ip'= DST IP
          persist ok; 'dst_ip_enqueue'= DST IP persist enqueue; 'dst_ip_fail'= DST IP
          persist fail; 'dst_ip_new_sess_cache'= DST IP new sess (cache);
          'dst_ip_new_sess_cache_fail'= DST IP new sess fail (c); 'dst_ip_new_sess_sel'=
          DST IP new sess (select); 'dst_ip_new_sess_sel_fail'= DST IP new sess fail (s);
          'dst_ip_hash_pri'= DST IP hash persist(pri); 'dst_ip_hash_enqueue'= DST IP hash
          persist(enQ); 'dst_ip_hash_sec'= DST IP hash persist(sec); 'dst_ip_hash_fail'=
          DST IP hash persist fail; 'cssl_sid_not_found'= Client SSL SID not found;
          'cssl_sid_match'= Client SSL SID match; 'cssl_sid_not_match'= Client SSL SID
          not match; 'sssl_sid_not_found'= Server SSL SID not found; 'sssl_sid_reset'=
          Server SSL SID reset; 'sssl_sid_match'= Server SSL SID match;
          'sssl_sid_not_match'= Server SSL SID not match; 'ssl_sid_persist_ok'= SSL SID
          persist ok; 'ssl_sid_persist_fail'= SSL SID persist fail; 'ssl_sid_session_ok'=
          Create SSL SID ok; 'ssl_sid_session_fail'= Create SSL SID fail;
          'cookie_persist_ok'= Cookie persist ok; 'cookie_persist_fail'= Cookie persist
          fail; 'cookie_not_found'= Persist cookie not found; 'cookie_pass_thru'= Persist
          cookie Pass-thru; 'cookie_invalid'= Invalid persist cookie;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            persist_cpu_list:
                description:
                - "Field persist_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            hash_tbl_trylock_fail:
                description:
                - "Hash tbl lock fail"
                type: str
            hash_tbl_create_ok:
                description:
                - "Hash tbl create ok"
                type: str
            hash_tbl_create_fail:
                description:
                - "Hash tbl create fail"
                type: str
            hash_tbl_free:
                description:
                - "Hash tbl free"
                type: str
            hash_tbl_rst_updown:
                description:
                - "Hash tbl reset (up/down)"
                type: str
            hash_tbl_rst_adddel:
                description:
                - "Hash tbl reset (add/del)"
                type: str
            url_hash_pri:
                description:
                - "URL hash persist (pri)"
                type: str
            url_hash_enqueue:
                description:
                - "URL hash persist (enQ)"
                type: str
            url_hash_sec:
                description:
                - "URL hash persist (sec)"
                type: str
            url_hash_fail:
                description:
                - "URL hash persist fail"
                type: str
            header_hash_pri:
                description:
                - "Header hash persist(pri)"
                type: str
            header_hash_enqueue:
                description:
                - "Header hash persist(enQ)"
                type: str
            header_hash_sec:
                description:
                - "Header hash persist(sec)"
                type: str
            header_hash_fail:
                description:
                - "Header hash persist fail"
                type: str
            src_ip:
                description:
                - "SRC IP persist ok"
                type: str
            src_ip_enqueue:
                description:
                - "SRC IP persist enqueue"
                type: str
            src_ip_fail:
                description:
                - "SRC IP persist fail"
                type: str
            src_ip_new_sess_cache:
                description:
                - "SRC IP new sess (cache)"
                type: str
            src_ip_new_sess_cache_fail:
                description:
                - "SRC IP new sess fail (c)"
                type: str
            src_ip_new_sess_sel:
                description:
                - "SRC IP new sess (select)"
                type: str
            src_ip_new_sess_sel_fail:
                description:
                - "SRC IP new sess fail (s)"
                type: str
            src_ip_hash_pri:
                description:
                - "SRC IP hash persist(pri)"
                type: str
            src_ip_hash_enqueue:
                description:
                - "SRC IP hash persist(enQ)"
                type: str
            src_ip_hash_sec:
                description:
                - "SRC IP hash persist(sec)"
                type: str
            src_ip_hash_fail:
                description:
                - "SRC IP hash persist fail"
                type: str
            src_ip_enforce:
                description:
                - "Enforce higher priority"
                type: str
            dst_ip:
                description:
                - "DST IP persist ok"
                type: str
            dst_ip_enqueue:
                description:
                - "DST IP persist enqueue"
                type: str
            dst_ip_fail:
                description:
                - "DST IP persist fail"
                type: str
            dst_ip_new_sess_cache:
                description:
                - "DST IP new sess (cache)"
                type: str
            dst_ip_new_sess_cache_fail:
                description:
                - "DST IP new sess fail (c)"
                type: str
            dst_ip_new_sess_sel:
                description:
                - "DST IP new sess (select)"
                type: str
            dst_ip_new_sess_sel_fail:
                description:
                - "DST IP new sess fail (s)"
                type: str
            dst_ip_hash_pri:
                description:
                - "DST IP hash persist(pri)"
                type: str
            dst_ip_hash_enqueue:
                description:
                - "DST IP hash persist(enQ)"
                type: str
            dst_ip_hash_sec:
                description:
                - "DST IP hash persist(sec)"
                type: str
            dst_ip_hash_fail:
                description:
                - "DST IP hash persist fail"
                type: str
            cssl_sid_not_found:
                description:
                - "Client SSL SID not found"
                type: str
            cssl_sid_match:
                description:
                - "Client SSL SID match"
                type: str
            cssl_sid_not_match:
                description:
                - "Client SSL SID not match"
                type: str
            sssl_sid_not_found:
                description:
                - "Server SSL SID not found"
                type: str
            sssl_sid_reset:
                description:
                - "Server SSL SID reset"
                type: str
            sssl_sid_match:
                description:
                - "Server SSL SID match"
                type: str
            sssl_sid_not_match:
                description:
                - "Server SSL SID not match"
                type: str
            ssl_sid_persist_ok:
                description:
                - "SSL SID persist ok"
                type: str
            ssl_sid_persist_fail:
                description:
                - "SSL SID persist fail"
                type: str
            ssl_sid_session_ok:
                description:
                - "Create SSL SID ok"
                type: str
            ssl_sid_session_fail:
                description:
                - "Create SSL SID fail"
                type: str
            cookie_persist_ok:
                description:
                - "Cookie persist ok"
                type: str
            cookie_persist_fail:
                description:
                - "Cookie persist fail"
                type: str
            cookie_not_found:
                description:
                - "Persist cookie not found"
                type: str
            cookie_pass_thru:
                description:
                - "Persist cookie Pass-thru"
                type: str
            cookie_invalid:
                description:
                - "Invalid persist cookie"
                type: str

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
    "oper",
    "sampling_enable",
    "stats",
    "uuid",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='str',
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'hash_tbl_trylock_fail', 'hash_tbl_create_ok',
                    'hash_tbl_create_fail', 'hash_tbl_free',
                    'hash_tbl_rst_updown', 'hash_tbl_rst_adddel',
                    'url_hash_pri', 'url_hash_enqueue', 'url_hash_sec',
                    'url_hash_fail', 'header_hash_pri', 'header_hash_enqueue',
                    'header_hash_sec', 'header_hash_fail', 'src_ip',
                    'src_ip_enqueue', 'src_ip_fail', 'src_ip_new_sess_cache',
                    'src_ip_new_sess_cache_fail', 'src_ip_new_sess_sel',
                    'src_ip_new_sess_sel_fail', 'src_ip_hash_pri',
                    'src_ip_hash_enqueue', 'src_ip_hash_sec',
                    'src_ip_hash_fail', 'src_ip_enforce', 'dst_ip',
                    'dst_ip_enqueue', 'dst_ip_fail', 'dst_ip_new_sess_cache',
                    'dst_ip_new_sess_cache_fail', 'dst_ip_new_sess_sel',
                    'dst_ip_new_sess_sel_fail', 'dst_ip_hash_pri',
                    'dst_ip_hash_enqueue', 'dst_ip_hash_sec',
                    'dst_ip_hash_fail', 'cssl_sid_not_found', 'cssl_sid_match',
                    'cssl_sid_not_match', 'sssl_sid_not_found',
                    'sssl_sid_reset', 'sssl_sid_match', 'sssl_sid_not_match',
                    'ssl_sid_persist_ok', 'ssl_sid_persist_fail',
                    'ssl_sid_session_ok', 'ssl_sid_session_fail',
                    'cookie_persist_ok', 'cookie_persist_fail',
                    'cookie_not_found', 'cookie_pass_thru', 'cookie_invalid'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'persist_cpu_list': {
                'type': 'list',
                'hash_tbl_trylock_fail': {
                    'type': 'int',
                },
                'hash_tbl_create_ok': {
                    'type': 'int',
                },
                'hash_tbl_create_fail': {
                    'type': 'int',
                },
                'hash_tbl_free': {
                    'type': 'int',
                },
                'hash_tbl_rst_updown': {
                    'type': 'int',
                },
                'hash_tbl_rst_adddel': {
                    'type': 'int',
                },
                'url_hash_pri': {
                    'type': 'int',
                },
                'url_hash_enqueue': {
                    'type': 'int',
                },
                'url_hash_sec': {
                    'type': 'int',
                },
                'url_hash_fail': {
                    'type': 'int',
                },
                'header_hash_pri': {
                    'type': 'int',
                },
                'header_hash_enqueue': {
                    'type': 'int',
                },
                'header_hash_sec': {
                    'type': 'int',
                },
                'header_hash_fail': {
                    'type': 'int',
                },
                'src_ip': {
                    'type': 'int',
                },
                'src_ip_enqueue': {
                    'type': 'int',
                },
                'src_ip_fail': {
                    'type': 'int',
                },
                'src_ip_new_sess_cache': {
                    'type': 'int',
                },
                'src_ip_new_sess_cache_fail': {
                    'type': 'int',
                },
                'src_ip_new_sess_sel': {
                    'type': 'int',
                },
                'src_ip_new_sess_sel_fail': {
                    'type': 'int',
                },
                'src_ip_hash_pri': {
                    'type': 'int',
                },
                'src_ip_hash_enqueue': {
                    'type': 'int',
                },
                'src_ip_hash_sec': {
                    'type': 'int',
                },
                'src_ip_hash_fail': {
                    'type': 'int',
                },
                'src_ip_enforce': {
                    'type': 'int',
                },
                'dst_ip': {
                    'type': 'int',
                },
                'dst_ip_enqueue': {
                    'type': 'int',
                },
                'dst_ip_fail': {
                    'type': 'int',
                },
                'dst_ip_new_sess_cache': {
                    'type': 'int',
                },
                'dst_ip_new_sess_cache_fail': {
                    'type': 'int',
                },
                'dst_ip_new_sess_sel': {
                    'type': 'int',
                },
                'dst_ip_new_sess_sel_fail': {
                    'type': 'int',
                },
                'dst_ip_hash_pri': {
                    'type': 'int',
                },
                'dst_ip_hash_enqueue': {
                    'type': 'int',
                },
                'dst_ip_hash_sec': {
                    'type': 'int',
                },
                'dst_ip_hash_fail': {
                    'type': 'int',
                },
                'cssl_sid_not_found': {
                    'type': 'int',
                },
                'cssl_sid_match': {
                    'type': 'int',
                },
                'cssl_sid_not_match': {
                    'type': 'int',
                },
                'sssl_sid_not_found': {
                    'type': 'int',
                },
                'sssl_sid_reset': {
                    'type': 'int',
                },
                'sssl_sid_match': {
                    'type': 'int',
                },
                'sssl_sid_not_match': {
                    'type': 'int',
                },
                'ssl_sid_persist_ok': {
                    'type': 'int',
                },
                'ssl_sid_persist_fail': {
                    'type': 'int',
                },
                'ssl_sid_session_ok': {
                    'type': 'int',
                },
                'ssl_sid_session_fail': {
                    'type': 'int',
                },
                'cookie_persist_ok': {
                    'type': 'int',
                },
                'cookie_persist_fail': {
                    'type': 'int',
                },
                'cookie_not_found': {
                    'type': 'int',
                },
                'cookie_pass_thru': {
                    'type': 'int',
                },
                'cookie_invalid': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            }
        },
        'stats': {
            'type': 'dict',
            'hash_tbl_trylock_fail': {
                'type': 'str',
            },
            'hash_tbl_create_ok': {
                'type': 'str',
            },
            'hash_tbl_create_fail': {
                'type': 'str',
            },
            'hash_tbl_free': {
                'type': 'str',
            },
            'hash_tbl_rst_updown': {
                'type': 'str',
            },
            'hash_tbl_rst_adddel': {
                'type': 'str',
            },
            'url_hash_pri': {
                'type': 'str',
            },
            'url_hash_enqueue': {
                'type': 'str',
            },
            'url_hash_sec': {
                'type': 'str',
            },
            'url_hash_fail': {
                'type': 'str',
            },
            'header_hash_pri': {
                'type': 'str',
            },
            'header_hash_enqueue': {
                'type': 'str',
            },
            'header_hash_sec': {
                'type': 'str',
            },
            'header_hash_fail': {
                'type': 'str',
            },
            'src_ip': {
                'type': 'str',
            },
            'src_ip_enqueue': {
                'type': 'str',
            },
            'src_ip_fail': {
                'type': 'str',
            },
            'src_ip_new_sess_cache': {
                'type': 'str',
            },
            'src_ip_new_sess_cache_fail': {
                'type': 'str',
            },
            'src_ip_new_sess_sel': {
                'type': 'str',
            },
            'src_ip_new_sess_sel_fail': {
                'type': 'str',
            },
            'src_ip_hash_pri': {
                'type': 'str',
            },
            'src_ip_hash_enqueue': {
                'type': 'str',
            },
            'src_ip_hash_sec': {
                'type': 'str',
            },
            'src_ip_hash_fail': {
                'type': 'str',
            },
            'src_ip_enforce': {
                'type': 'str',
            },
            'dst_ip': {
                'type': 'str',
            },
            'dst_ip_enqueue': {
                'type': 'str',
            },
            'dst_ip_fail': {
                'type': 'str',
            },
            'dst_ip_new_sess_cache': {
                'type': 'str',
            },
            'dst_ip_new_sess_cache_fail': {
                'type': 'str',
            },
            'dst_ip_new_sess_sel': {
                'type': 'str',
            },
            'dst_ip_new_sess_sel_fail': {
                'type': 'str',
            },
            'dst_ip_hash_pri': {
                'type': 'str',
            },
            'dst_ip_hash_enqueue': {
                'type': 'str',
            },
            'dst_ip_hash_sec': {
                'type': 'str',
            },
            'dst_ip_hash_fail': {
                'type': 'str',
            },
            'cssl_sid_not_found': {
                'type': 'str',
            },
            'cssl_sid_match': {
                'type': 'str',
            },
            'cssl_sid_not_match': {
                'type': 'str',
            },
            'sssl_sid_not_found': {
                'type': 'str',
            },
            'sssl_sid_reset': {
                'type': 'str',
            },
            'sssl_sid_match': {
                'type': 'str',
            },
            'sssl_sid_not_match': {
                'type': 'str',
            },
            'ssl_sid_persist_ok': {
                'type': 'str',
            },
            'ssl_sid_persist_fail': {
                'type': 'str',
            },
            'ssl_sid_session_ok': {
                'type': 'str',
            },
            'ssl_sid_session_fail': {
                'type': 'str',
            },
            'cookie_persist_ok': {
                'type': 'str',
            },
            'cookie_persist_fail': {
                'type': 'str',
            },
            'cookie_not_found': {
                'type': 'str',
            },
            'cookie_pass_thru': {
                'type': 'str',
            },
            'cookie_invalid': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/persist"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/persist"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["persist"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["persist"].get(k) != v:
            change_results["changed"] = True
            config_changes["persist"][k] = v

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
    payload = utils.build_json("persist", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'Not Found':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
            elif module.params.get("get_type") == "oper":
                result["axapi_calls"].append(
                    api_client.get_oper(module.client,
                                        existing_url(module),
                                        params=module.params))
            elif module.params.get("get_type") == "stats":
                result["axapi_calls"].append(
                    api_client.get_stats(module.client,
                                         existing_url(module),
                                         params=module.params))
    except a10_ex.ACOSException as ex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        raise gex
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
