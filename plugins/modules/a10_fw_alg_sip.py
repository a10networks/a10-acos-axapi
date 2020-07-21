#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_alg_sip
description:
    - Change Firewall SIP ALG Settings
short_description: Configures A10 fw.alg.sip
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    default_port_disable:
        description:
        - "'default-port-disable'= Disable SIP ALG default port 5060;"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            method_register:
                description:
                - "Method REGISTER"
            stat_request:
                description:
                - "Request Received"
            method_publish:
                description:
                - "Method PUBLISH"
            method_cancel:
                description:
                - "Method CANCEL"
            method_unknown:
                description:
                - "Method Unknown"
            method_update:
                description:
                - "Method UPDATE"
            method_subscribe:
                description:
                - "Method SUBSCRIBE"
            method_invite:
                description:
                - "Method INVITE"
            method_options:
                description:
                - "Method OPTIONS"
            method_prack:
                description:
                - "Method PRACK"
            method_notify:
                description:
                - "Method NOTIFY"
            method_info:
                description:
                - "Method INFO"
            method_ack:
                description:
                - "Method ACK"
            method_refer:
                description:
                - "Method REFER"
            stat_response:
                description:
                - "Response Received"
            method_bye:
                description:
                - "Method BYE"
            method_message:
                description:
                - "Method MESSAGE"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'stat-request'= Request Received; 'stat-response'= Response
          Received; 'method-register'= Method REGISTER; 'method-invite'= Method INVITE;
          'method-ack'= Method ACK; 'method-cancel'= Method CANCEL; 'method-bye'= Method
          BYE; 'method-options'= Method OPTIONS; 'method-prack'= Method PRACK; 'method-
          subscribe'= Method SUBSCRIBE; 'method-notify'= Method NOTIFY; 'method-publish'=
          Method PUBLISH; 'method-info'= Method INFO; 'method-refer'= Method REFER;
          'method-message'= Method MESSAGE; 'method-update'= Method UPDATE; 'method-
          unknown'= Method Unknown; 'parse-error'= Message Parse Error; 'keep-alive'=
          Keep Alive; 'contact-error'= Contact Process Error; 'sdp-error'= SDP Process
          Error; 'rtp-port-no-op'= RTP Port No Op; 'rtp-rtcp-port-success'= RTP RTCP Port
          Success; 'rtp-port-failure'= RTP Port Failure; 'rtcp-port-failure'= RTCP Port
          Failure; 'contact-port-no-op'= Contact Port No Op; 'contact-port-success'=
          Contact Port Success; 'contact-port-failure'= Contact Port Failure; 'contact-
          new'= Contact Alloc; 'contact-alloc-failure'= Contact Alloc Failure; 'contact-
          eim'= Contact EIM; 'contact-eim-set'= Contact EIM Set; 'rtp-new'= RTP Alloc;
          'rtp-alloc-failure'= RTP Alloc Failure; 'rtp-eim'= RTP EIM; 'helper-found'= SMP
          Helper Conn Found; 'helper-created'= SMP Helper Conn Created; 'helper-deleted'=
          SMP Helper Conn Already Deleted; 'helper-freed'= SMP Helper Conn Freed;
          'helper-failure'= SMP Helper Failure;"
    uuid:
        description:
        - "uuid of the object"
        required: False


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
    "default_port_disable",
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
        'default_port_disable': {
            'type': 'str',
            'choices': ['default-port-disable']
        },
        'stats': {
            'type': 'dict',
            'method_register': {
                'type': 'str',
            },
            'stat_request': {
                'type': 'str',
            },
            'method_publish': {
                'type': 'str',
            },
            'method_cancel': {
                'type': 'str',
            },
            'method_unknown': {
                'type': 'str',
            },
            'method_update': {
                'type': 'str',
            },
            'method_subscribe': {
                'type': 'str',
            },
            'method_invite': {
                'type': 'str',
            },
            'method_options': {
                'type': 'str',
            },
            'method_prack': {
                'type': 'str',
            },
            'method_notify': {
                'type': 'str',
            },
            'method_info': {
                'type': 'str',
            },
            'method_ack': {
                'type': 'str',
            },
            'method_refer': {
                'type': 'str',
            },
            'stat_response': {
                'type': 'str',
            },
            'method_bye': {
                'type': 'str',
            },
            'method_message': {
                'type': 'str',
            }
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'stat-request', 'stat-response', 'method-register',
                    'method-invite', 'method-ack', 'method-cancel',
                    'method-bye', 'method-options', 'method-prack',
                    'method-subscribe', 'method-notify', 'method-publish',
                    'method-info', 'method-refer', 'method-message',
                    'method-update', 'method-unknown', 'parse-error',
                    'keep-alive', 'contact-error', 'sdp-error',
                    'rtp-port-no-op', 'rtp-rtcp-port-success',
                    'rtp-port-failure', 'rtcp-port-failure',
                    'contact-port-no-op', 'contact-port-success',
                    'contact-port-failure', 'contact-new',
                    'contact-alloc-failure', 'contact-eim', 'contact-eim-set',
                    'rtp-new', 'rtp-alloc-failure', 'rtp-eim', 'helper-found',
                    'helper-created', 'helper-deleted', 'helper-freed',
                    'helper-failure'
                ]
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/alg/sip"

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
    url_base = "/axapi/v3/fw/alg/sip"

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
        for k, v in payload["sip"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["sip"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["sip"][k] = v
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
    payload = build_json("sip", module)
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
