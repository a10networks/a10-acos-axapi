#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_sip
description:
    - SIP Template
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
    name:
        description:
        - "SIP Template Name"
        type: str
        required: True
    alg_source_nat:
        description:
        - "Translate source IP to NAT IP in SIP message when source NAT is used"
        type: bool
        required: False
    alg_dest_nat:
        description:
        - "Translate VIP to real server IP in SIP message when destination NAT is used"
        type: bool
        required: False
    call_id_persist_disable:
        description:
        - "Disable call-ID persistence"
        type: bool
        required: False
    client_keep_alive:
        description:
        - "Respond client keep-alive packet directly instead of forwarding to server"
        type: bool
        required: False
    pstn_gw:
        description:
        - "configure pstn gw host name for tel= uri translate to sip= uri (Hostname
          String, default is 'pstn')"
        type: str
        required: False
    client_request_header:
        description:
        - "Field client_request_header"
        type: list
        required: False
        suboptions:
            client_request_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
                type: str
            client_request_erase_all:
                description:
                - "Erase all headers"
                type: bool
            client_request_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name=value'))"
                type: str
            insert_condition_client_request:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    client_response_header:
        description:
        - "Field client_response_header"
        type: list
        required: False
        suboptions:
            client_response_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
                type: str
            client_response_erase_all:
                description:
                - "Erase all headers"
                type: bool
            client_response_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name=value'))"
                type: str
            insert_condition_client_response:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    exclude_translation:
        description:
        - "Field exclude_translation"
        type: list
        required: False
        suboptions:
            translation_value:
                description:
                - "'start-line'= SIP request line or status line; 'header'= SIP message headers;
          'body'= SIP message body;"
                type: str
            header_string:
                description:
                - "SIP header name"
                type: str
    failed_client_selection:
        description:
        - "Define action when select client fail"
        type: bool
        required: False
    drop_when_client_fail:
        description:
        - "Drop current SIP message when select client fail"
        type: bool
        required: False
    failed_client_selection_message:
        description:
        - "Send SIP message (includs status code) to server when select client
          fail(Format= 3 digits(1XX~6XX) space reason)"
        type: str
        required: False
    failed_server_selection:
        description:
        - "Define action when select server fail"
        type: bool
        required: False
    drop_when_server_fail:
        description:
        - "Drop current SIP message when select server fail"
        type: bool
        required: False
    failed_server_selection_message:
        description:
        - "Send SIP message (includs status code) to client when select server
          fail(Format= 3 digits(1XX~6XX) space reason)"
        type: str
        required: False
    insert_client_ip:
        description:
        - "Insert Client IP address into SIP header"
        type: bool
        required: False
    keep_server_ip_if_match_acl:
        description:
        - "Use Real Server IP for addresses matching the ACL for a Call-Id"
        type: bool
        required: False
    acl_id:
        description:
        - "ACL id"
        type: int
        required: False
    acl_name_value:
        description:
        - "IPv4 Access List Name"
        type: str
        required: False
    service_group:
        description:
        - "service group name"
        type: str
        required: False
    server_keep_alive:
        description:
        - "Send server keep-alive packet for every persist connection when enable conn-
          reuse"
        type: bool
        required: False
    interval:
        description:
        - "The interval of keep-alive packet for each persist connection (second)"
        type: int
        required: False
    server_request_header:
        description:
        - "Field server_request_header"
        type: list
        required: False
        suboptions:
            server_request_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
                type: str
            server_request_erase_all:
                description:
                - "Erase all headers"
                type: bool
            server_request_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name=value'))"
                type: str
            insert_condition_server_request:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    server_response_header:
        description:
        - "Field server_response_header"
        type: list
        required: False
        suboptions:
            server_response_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
                type: str
            server_response_erase_all:
                description:
                - "Erase all headers"
                type: bool
            server_response_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name=value'))"
                type: str
            insert_condition_server_response:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    smp_call_id_rtp_session:
        description:
        - "Create the across cpu call-id rtp session"
        type: bool
        required: False
    server_selection_per_request:
        description:
        - "Force server selection on every SIP request"
        type: bool
        required: False
    timeout:
        description:
        - "Time in minutes"
        type: int
        required: False
    dialog_aware:
        description:
        - "Permit system processes dialog session"
        type: bool
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
    "acl_id",
    "acl_name_value",
    "alg_dest_nat",
    "alg_source_nat",
    "call_id_persist_disable",
    "client_keep_alive",
    "client_request_header",
    "client_response_header",
    "dialog_aware",
    "drop_when_client_fail",
    "drop_when_server_fail",
    "exclude_translation",
    "failed_client_selection",
    "failed_client_selection_message",
    "failed_server_selection",
    "failed_server_selection_message",
    "insert_client_ip",
    "interval",
    "keep_server_ip_if_match_acl",
    "name",
    "pstn_gw",
    "server_keep_alive",
    "server_request_header",
    "server_response_header",
    "server_selection_per_request",
    "service_group",
    "smp_call_id_rtp_session",
    "timeout",
    "user_tag",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'alg_source_nat': {
            'type': 'bool',
        },
        'alg_dest_nat': {
            'type': 'bool',
        },
        'call_id_persist_disable': {
            'type': 'bool',
        },
        'client_keep_alive': {
            'type': 'bool',
        },
        'pstn_gw': {
            'type': 'str',
        },
        'client_request_header': {
            'type': 'list',
            'client_request_header_erase': {
                'type': 'str',
            },
            'client_request_erase_all': {
                'type': 'bool',
            },
            'client_request_header_insert': {
                'type': 'str',
            },
            'insert_condition_client_request': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
            }
        },
        'client_response_header': {
            'type': 'list',
            'client_response_header_erase': {
                'type': 'str',
            },
            'client_response_erase_all': {
                'type': 'bool',
            },
            'client_response_header_insert': {
                'type': 'str',
            },
            'insert_condition_client_response': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
            }
        },
        'exclude_translation': {
            'type': 'list',
            'translation_value': {
                'type': 'str',
                'choices': ['start-line', 'header', 'body']
            },
            'header_string': {
                'type': 'str',
            }
        },
        'failed_client_selection': {
            'type': 'bool',
        },
        'drop_when_client_fail': {
            'type': 'bool',
        },
        'failed_client_selection_message': {
            'type': 'str',
        },
        'failed_server_selection': {
            'type': 'bool',
        },
        'drop_when_server_fail': {
            'type': 'bool',
        },
        'failed_server_selection_message': {
            'type': 'str',
        },
        'insert_client_ip': {
            'type': 'bool',
        },
        'keep_server_ip_if_match_acl': {
            'type': 'bool',
        },
        'acl_id': {
            'type': 'int',
        },
        'acl_name_value': {
            'type': 'str',
        },
        'service_group': {
            'type': 'str',
        },
        'server_keep_alive': {
            'type': 'bool',
        },
        'interval': {
            'type': 'int',
        },
        'server_request_header': {
            'type': 'list',
            'server_request_header_erase': {
                'type': 'str',
            },
            'server_request_erase_all': {
                'type': 'bool',
            },
            'server_request_header_insert': {
                'type': 'str',
            },
            'insert_condition_server_request': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
            }
        },
        'server_response_header': {
            'type': 'list',
            'server_response_header_erase': {
                'type': 'str',
            },
            'server_response_erase_all': {
                'type': 'bool',
            },
            'server_response_header_insert': {
                'type': 'str',
            },
            'insert_condition_server_response': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
            }
        },
        'smp_call_id_rtp_session': {
            'type': 'bool',
        },
        'server_selection_per_request': {
            'type': 'bool',
        },
        'timeout': {
            'type': 'int',
        },
        'dialog_aware': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/sip/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


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
    url_base = "/axapi/v3/slb/template/sip/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
