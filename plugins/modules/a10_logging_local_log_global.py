#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_logging_local_log_global
description:
    - Field global
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
                - "'all'= all; 'enqueue'= Total local-log enqueue; 'enqueue-full'= Total local-log
          queue full; 'enqueue-error'= Total local-log enqueue error; 'dequeue'= Total
          local-log dequeue; 'dequeue-error'= Total local-log dequeue processing error;
          'raw-log'= Total local-log raw logs; 'raw-log-error'= Total raw log logging
          error; 'log-summarized'= Total raw log summarized; 'l1-log-summarized'= Total
          layer 1 log summarized; 'l2-log-summarized'= Total layer 2 log summarized;
          'log-summarized-error'= Total local-log summarization error; 'aam-db'= Total
          local-log AAM raw database; 'ep-db'= Total local-log EP raw database; 'fi-db'=
          Total local-log File-Inspection raw database; 'fw-db'= Total local-log Firewall
          raw database; 'aam-top-user-db'= Total local-log AAM top user summary database;
          'ep-top-user-db'= Total local-log EP top user summary database; 'ep-top-src-
          db'= Total local-log EP top client summary database; 'ep-top-dst-db'= Total
          local-log EP top destination summary database; 'ep-top-domain-db'= Total local-
          log EP top domain summary database; 'ep-top-web-category-db'= Total local-log
          EP top web-category summary database; 'ep-top-host-db'= Total local-log EP top
          host summary database; 'fi-top-src-db'= Total local-log File-Inspection top
          source summary database; 'fi-top-dst-db'= Total local-log File-Inspection top
          destination summary database; 'fi-top-filename-db'= Total local-log File-
          Inspection top file name summary database; 'fi-top-file-ext-db'= Total local-
          log File-Inspection top file extension summary database; 'fi-top-url-db'= Total
          local-log File-Inspection top URL summary database; 'fw-top-app-db'= Total
          local-log Friewall top application summary database; 'fw-top-src-db'= Total
          local-log Friewall top source summary database; 'fw-top-app-src-db'= Total
          local-log Friewall top application and source summary database; 'fw-top-
          category-db'= Total local-log Friewall top category summary database; 'db-
          erro'= Total local-log database create error; 'query'= Total local-log axapi
          query; 'response'= Total local-log axapi response; 'query-error'= Total local-
          log axapi query error;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            enqueue:
                description:
                - "Total local-log enqueue"
                type: str
            enqueue_full:
                description:
                - "Total local-log queue full"
                type: str
            enqueue_error:
                description:
                - "Total local-log enqueue error"
                type: str
            dequeue:
                description:
                - "Total local-log dequeue"
                type: str
            dequeue_error:
                description:
                - "Total local-log dequeue processing error"
                type: str
            raw_log:
                description:
                - "Total local-log raw logs"
                type: str
            raw_log_error:
                description:
                - "Total raw log logging error"
                type: str
            log_summarized:
                description:
                - "Total raw log summarized"
                type: str
            l1_log_summarized:
                description:
                - "Total layer 1 log summarized"
                type: str
            l2_log_summarized:
                description:
                - "Total layer 2 log summarized"
                type: str
            log_summarized_error:
                description:
                - "Total local-log summarization error"
                type: str
            aam_db:
                description:
                - "Total local-log AAM raw database"
                type: str
            ep_db:
                description:
                - "Total local-log EP raw database"
                type: str
            fi_db:
                description:
                - "Total local-log File-Inspection raw database"
                type: str
            fw_db:
                description:
                - "Total local-log Firewall raw database"
                type: str
            aam_top_user_db:
                description:
                - "Total local-log AAM top user summary database"
                type: str
            ep_top_user_db:
                description:
                - "Total local-log EP top user summary database"
                type: str
            ep_top_src_db:
                description:
                - "Total local-log EP top client summary database"
                type: str
            ep_top_dst_db:
                description:
                - "Total local-log EP top destination summary database"
                type: str
            ep_top_domain_db:
                description:
                - "Total local-log EP top domain summary database"
                type: str
            ep_top_web_category_db:
                description:
                - "Total local-log EP top web-category summary database"
                type: str
            ep_top_host_db:
                description:
                - "Total local-log EP top host summary database"
                type: str
            fi_top_src_db:
                description:
                - "Total local-log File-Inspection top source summary database"
                type: str
            fi_top_dst_db:
                description:
                - "Total local-log File-Inspection top destination summary database"
                type: str
            fi_top_filename_db:
                description:
                - "Total local-log File-Inspection top file name summary database"
                type: str
            fi_top_file_ext_db:
                description:
                - "Total local-log File-Inspection top file extension summary database"
                type: str
            fi_top_url_db:
                description:
                - "Total local-log File-Inspection top URL summary database"
                type: str
            fw_top_app_db:
                description:
                - "Total local-log Friewall top application summary database"
                type: str
            fw_top_src_db:
                description:
                - "Total local-log Friewall top source summary database"
                type: str
            fw_top_app_src_db:
                description:
                - "Total local-log Friewall top application and source summary database"
                type: str
            fw_top_category_db:
                description:
                - "Total local-log Friewall top category summary database"
                type: str
            db_erro:
                description:
                - "Total local-log database create error"
                type: str
            query:
                description:
                - "Total local-log axapi query"
                type: str
            response:
                description:
                - "Total local-log axapi response"
                type: str
            query_error:
                description:
                - "Total local-log axapi query error"
                type: str

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "sampling_enable",
    "stats",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


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
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
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
                    'all', 'enqueue', 'enqueue-full', 'enqueue-error',
                    'dequeue', 'dequeue-error', 'raw-log', 'raw-log-error',
                    'log-summarized', 'l1-log-summarized', 'l2-log-summarized',
                    'log-summarized-error', 'aam-db', 'ep-db', 'fi-db',
                    'fw-db', 'aam-top-user-db', 'ep-top-user-db',
                    'ep-top-src-db', 'ep-top-dst-db', 'ep-top-domain-db',
                    'ep-top-web-category-db', 'ep-top-host-db',
                    'fi-top-src-db', 'fi-top-dst-db', 'fi-top-filename-db',
                    'fi-top-file-ext-db', 'fi-top-url-db', 'fw-top-app-db',
                    'fw-top-src-db', 'fw-top-app-src-db', 'fw-top-category-db',
                    'db-erro', 'query', 'response', 'query-error'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'enqueue': {
                'type': 'str',
            },
            'enqueue_full': {
                'type': 'str',
            },
            'enqueue_error': {
                'type': 'str',
            },
            'dequeue': {
                'type': 'str',
            },
            'dequeue_error': {
                'type': 'str',
            },
            'raw_log': {
                'type': 'str',
            },
            'raw_log_error': {
                'type': 'str',
            },
            'log_summarized': {
                'type': 'str',
            },
            'l1_log_summarized': {
                'type': 'str',
            },
            'l2_log_summarized': {
                'type': 'str',
            },
            'log_summarized_error': {
                'type': 'str',
            },
            'aam_db': {
                'type': 'str',
            },
            'ep_db': {
                'type': 'str',
            },
            'fi_db': {
                'type': 'str',
            },
            'fw_db': {
                'type': 'str',
            },
            'aam_top_user_db': {
                'type': 'str',
            },
            'ep_top_user_db': {
                'type': 'str',
            },
            'ep_top_src_db': {
                'type': 'str',
            },
            'ep_top_dst_db': {
                'type': 'str',
            },
            'ep_top_domain_db': {
                'type': 'str',
            },
            'ep_top_web_category_db': {
                'type': 'str',
            },
            'ep_top_host_db': {
                'type': 'str',
            },
            'fi_top_src_db': {
                'type': 'str',
            },
            'fi_top_dst_db': {
                'type': 'str',
            },
            'fi_top_filename_db': {
                'type': 'str',
            },
            'fi_top_file_ext_db': {
                'type': 'str',
            },
            'fi_top_url_db': {
                'type': 'str',
            },
            'fw_top_app_db': {
                'type': 'str',
            },
            'fw_top_src_db': {
                'type': 'str',
            },
            'fw_top_app_src_db': {
                'type': 'str',
            },
            'fw_top_category_db': {
                'type': 'str',
            },
            'db_erro': {
                'type': 'str',
            },
            'query': {
                'type': 'str',
            },
            'response': {
                'type': 'str',
            },
            'query_error': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/logging/local-log/global"

    f_dict = {}

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/logging/local-log/global"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)


def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["global"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["global"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["global"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result


def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("global", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result


def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)


def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def run_command(module):
    run_errors = []

    result = dict(changed=False, original_message="", message="", result={})

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

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
