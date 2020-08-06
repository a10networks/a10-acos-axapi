#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_fixed_nat_alg_sip
description:
    - Change Fixed NAT SIP ALG Settings
short_description: Configures A10 cgnv6.fixed.nat.alg.sip
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'method-register'= SIP Method REGISTER; 'method-invite'= SIP Method
          INVITE; 'method-ack'= SIP Method ACK; 'method-cancel'= SIP Method CANCEL;
          'method-bye'= SIP Method BYE; 'method-options'= SIP Method OPTIONS; 'method-
          prack'= SIP Method PRACK; 'method-subscribe'= SIP Method SUBSCRIBE; 'method-
          notify'= SIP Method NOTIFY; 'method-publish'= SIP Method PUBLISH; 'method-
          info'= SIP Method INFO; 'method-refer'= SIP Method REFER; 'method-message'= SIP
          Method MESSAGE; 'method-update'= SIP Method UPDATE; 'method-unknown'= SIP
          Method UNKNOWN; 'parse-error'= SIP Message Parse Error; 'req-uri-op-failrue'=
          SIP Operate Request Uri Failure; 'via-hdr-op-failrue'= SIP Operate Via Header
          Failure; 'contact-hdr-op-failrue'= SIP Operate Contact Header Failure; 'from-
          hdr-op-failrue'= SIP Operate From Header Failure; 'to-hdr-op-failrue'= SIP
          Operate To Header Failure; 'route-hdr-op-failrue'= SIP Operate Route Header
          Failure; 'record-route-hdr-op-failrue'= SIP Operate Record-Route Header
          Failure; 'content-length-hdr-op-failrue'= SIP Operate Content-Length Failure;
          'third-party-registration'= SIP Third-Party Registration; 'conn-ext-creation-
          failure'= SIP Create Connection Extension Failure; 'alloc-contact-port-
          failure'= SIP Alloc Contact Port Failure; 'outside-contact-port-mismatch'= SIP
          Outside Contact Port Mismatch NAT Port; 'inside-contact-port-mismatch'= SIP
          Inside Contact Port Mismatch; 'third-party-sdp'= SIP Third-Party SDP; 'sdp-
          process-candidate-failure'= SIP Operate SDP Media Candidate Attribute Failure;
          'sdp-op-failure'= SIP Operate SDP Failure; 'sdp-alloc-port-map-success'= SIP
          Alloc SDP Port Map Success; 'sdp-alloc-port-map-failure'= SIP Alloc SDP Port
          Map Failure; 'modify-failure'= SIP Message Modify Failure; 'rewrite-failure'=
          SIP Message Rewrite Failure; 'tcp-out-of-order-drop'= TCP Out-of-Order Drop;
          'smp-conn-alloc-failure'= SMP Helper Conn Alloc Failure; 'helper-found'= SMP
          Helper Conn Found; 'helper-created'= SMP Helper Conn Created; 'helper-deleted'=
          SMP Helper Conn Already Deleted; 'helper-freed'= SMP Helper Conn Freed;
          'helper-failure'= SMP Helper Failure;"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            method_register:
                description:
                - "SIP Method REGISTER"
            method_invite:
                description:
                - "SIP Method INVITE"
            method_publish:
                description:
                - "SIP Method PUBLISH"
            method_unknown:
                description:
                - "SIP Method UNKNOWN"
            method_update:
                description:
                - "SIP Method UPDATE"
            method_subscribe:
                description:
                - "SIP Method SUBSCRIBE"
            method_options:
                description:
                - "SIP Method OPTIONS"
            method_prack:
                description:
                - "SIP Method PRACK"
            method_notify:
                description:
                - "SIP Method NOTIFY"
            method_info:
                description:
                - "SIP Method INFO"
            method_ack:
                description:
                - "SIP Method ACK"
            method_refer:
                description:
                - "SIP Method REFER"
            method_cancel:
                description:
                - "SIP Method CANCEL"
            method_bye:
                description:
                - "SIP Method BYE"
            method_message:
                description:
                - "SIP Method MESSAGE"
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
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'method-register', 'method-invite', 'method-ack',
                    'method-cancel', 'method-bye', 'method-options',
                    'method-prack', 'method-subscribe', 'method-notify',
                    'method-publish', 'method-info', 'method-refer',
                    'method-message', 'method-update', 'method-unknown',
                    'parse-error', 'req-uri-op-failrue', 'via-hdr-op-failrue',
                    'contact-hdr-op-failrue', 'from-hdr-op-failrue',
                    'to-hdr-op-failrue', 'route-hdr-op-failrue',
                    'record-route-hdr-op-failrue',
                    'content-length-hdr-op-failrue',
                    'third-party-registration', 'conn-ext-creation-failure',
                    'alloc-contact-port-failure',
                    'outside-contact-port-mismatch',
                    'inside-contact-port-mismatch', 'third-party-sdp',
                    'sdp-process-candidate-failure', 'sdp-op-failure',
                    'sdp-alloc-port-map-success', 'sdp-alloc-port-map-failure',
                    'modify-failure', 'rewrite-failure',
                    'tcp-out-of-order-drop', 'smp-conn-alloc-failure',
                    'helper-found', 'helper-created', 'helper-deleted',
                    'helper-freed', 'helper-failure'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'method_register': {
                'type': 'str',
            },
            'method_invite': {
                'type': 'str',
            },
            'method_publish': {
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
            'method_cancel': {
                'type': 'str',
            },
            'method_bye': {
                'type': 'str',
            },
            'method_message': {
                'type': 'str',
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
    url_base = "/axapi/v3/cgnv6/fixed-nat/alg/sip"

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
    url_base = "/axapi/v3/cgnv6/fixed-nat/alg/sip"

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
