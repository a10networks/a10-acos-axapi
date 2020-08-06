#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_stateful_firewall_global
description:
    - Stateful Firewall Configuration (default=disabled)
short_description: Configures A10 cgnv6.stateful.firewall.global
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
    respond_to_user_mac:
        description:
        - "Use the user's source MAC for the next hop rather than the routing table
          (default= off)"
        required: False
    stateful_firewall_value:
        description:
        - "'enable'= Enable stateful firewall;"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            session_creation_failure:
                description:
                - "Session Creation Failure"
            tcp_packet_process:
                description:
                - "TCP Packet Process"
            udp_fullcone_freed:
                description:
                - "UDP Full-cone Freed"
            outbound_session_created:
                description:
                - "Outbound Session Created"
            tcp_fullcone_created:
                description:
                - "TCP Full-cone Created"
            fullcone_creation_failure:
                description:
                - "Full-Cone Creation Failure"
            one_arm_drop:
                description:
                - "One-Arm Drop"
            packet_inbound_deny:
                description:
                - "Inbound Packet Denied"
            inbound_session_created:
                description:
                - "Inbound Session Created"
            udp_fullcone_created:
                description:
                - "UDP Full-cone Created"
            other_session_created:
                description:
                - "Other Session Created"
            udp_session_created:
                description:
                - "UDP Session Created"
            udp_packet_process:
                description:
                - "UDP Packet Process"
            no_fwd_route:
                description:
                - "No Forward Route"
            tcp_session_created:
                description:
                - "TCP Session Created"
            other_session_freed:
                description:
                - "Other Session Freed"
            eif_process:
                description:
                - "Endpnt-Independent Filter Matched"
            inbound_session_freed:
                description:
                - "Inbound Session Freed"
            udp_session_freed:
                description:
                - "UDP Session Freed"
            no_rev_route:
                description:
                - "No Reverse Route"
            packet_process_failure:
                description:
                - "Packet Error Drop"
            tcp_session_freed:
                description:
                - "TCP Session Freed"
            other_packet_process:
                description:
                - "Other Packet Process"
            tcp_fullcone_freed:
                description:
                - "TCP Full-cone Freed"
            outbound_session_freed:
                description:
                - "Outbound Session Freed"
            no_class_list_match:
                description:
                - "No Class-List Match Drop"
            packet_standby_drop:
                description:
                - "Standby Drop"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'tcp_packet_process'= TCP Packet Process; 'udp_packet_process'= UDP
          Packet Process; 'other_packet_process'= Other Packet Process;
          'packet_inbound_deny'= Inbound Packet Denied; 'packet_process_failure'= Packet
          Error Drop; 'outbound_session_created'= Outbound Session Created;
          'outbound_session_freed'= Outbound Session Freed; 'inbound_session_created'=
          Inbound Session Created; 'inbound_session_freed'= Inbound Session Freed;
          'tcp_session_created'= TCP Session Created; 'tcp_session_freed'= TCP Session
          Freed; 'udp_session_created'= UDP Session Created; 'udp_session_freed'= UDP
          Session Freed; 'other_session_created'= Other Session Created;
          'other_session_freed'= Other Session Freed; 'session_creation_failure'= Session
          Creation Failure; 'no_fwd_route'= No Forward Route; 'no_rev_route'= No Reverse
          Route; 'packet_standby_drop'= Standby Drop; 'tcp_fullcone_created'= TCP Full-
          cone Created; 'tcp_fullcone_freed'= TCP Full-cone Freed;
          'udp_fullcone_created'= UDP Full-cone Created; 'udp_fullcone_freed'= UDP Full-
          cone Freed; 'fullcone_creation_failure'= Full-Cone Creation Failure;
          'eif_process'= Endpnt-Independent Filter Matched; 'one_arm_drop'= One-Arm Drop;
          'no_class_list_match'= No Class-List Match Drop;
          'outbound_session_created_shadow'= Outbound Session Created Shadow;
          'outbound_session_freed_shadow'= Outbound Session Freed Shadow;
          'inbound_session_created_shadow'= Inbound Session Created Shadow;
          'inbound_session_freed_shadow'= Inbound Session Freed Shadow;
          'tcp_session_created_shadow'= TCP Session Created Shadow;
          'tcp_session_freed_shadow'= TCP Session Freed Shadow;
          'udp_session_created_shadow'= UDP Session Created Shadow;
          'udp_session_freed_shadow'= UDP Session Freed Shadow;
          'other_session_created_shadow'= Other Session Created Shadow;
          'other_session_freed_shadow'= Other Session Freed Shadow;
          'session_creation_failure_shadow'= Session Creation Failure Shadow;
          'bad_session_freed'= Bad Session Proto on Free; 'ctl_mem_alloc'= Memory Alloc;
          'ctl_mem_free'= Memory Free; 'tcp_fullcone_created_shadow'= TCP Full-cone
          Created Shadow; 'tcp_fullcone_freed_shadow'= TCP Full-cone Freed Shadow;
          'udp_fullcone_created_shadow'= UDP Full-cone Created Shadow;
          'udp_fullcone_freed_shadow'= UDP Full-cone Freed Shadow; 'fullcone_in_del_q'=
          Full-cone Found in Delete Queue; 'fullcone_overflow_eim'= EIM Overflow;
          'fullcone_overflow_eif'= EIF Overflow; 'fullcone_free_found'= Full-cone Free
          Found From Conn; 'fullcone_free_retry_lookup'= Full-cone Retry Look-up;
          'fullcone_free_not_found'= Full-cone Free Not Found; 'eif_limit_exceeded'= EIF
          Limit Exceeded; 'eif_disable_drop'= EIF Disable Drop; 'eif_process_failure'=
          EIF Process Failure; 'eif_filtered'= EIF Filtered;
          'ha_standby_session_created'= HA Standby Session Created;
          'ha_standby_session_eim'= HA Standby Session EIM; 'ha_standby_session_eif'= HA
          Standby Session EIF;"
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
    "respond_to_user_mac",
    "sampling_enable",
    "stateful_firewall_value",
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
        'respond_to_user_mac': {
            'type': 'bool',
        },
        'stateful_firewall_value': {
            'type': 'str',
            'choices': ['enable']
        },
        'stats': {
            'type': 'dict',
            'session_creation_failure': {
                'type': 'str',
            },
            'tcp_packet_process': {
                'type': 'str',
            },
            'udp_fullcone_freed': {
                'type': 'str',
            },
            'outbound_session_created': {
                'type': 'str',
            },
            'tcp_fullcone_created': {
                'type': 'str',
            },
            'fullcone_creation_failure': {
                'type': 'str',
            },
            'one_arm_drop': {
                'type': 'str',
            },
            'packet_inbound_deny': {
                'type': 'str',
            },
            'inbound_session_created': {
                'type': 'str',
            },
            'udp_fullcone_created': {
                'type': 'str',
            },
            'other_session_created': {
                'type': 'str',
            },
            'udp_session_created': {
                'type': 'str',
            },
            'udp_packet_process': {
                'type': 'str',
            },
            'no_fwd_route': {
                'type': 'str',
            },
            'tcp_session_created': {
                'type': 'str',
            },
            'other_session_freed': {
                'type': 'str',
            },
            'eif_process': {
                'type': 'str',
            },
            'inbound_session_freed': {
                'type': 'str',
            },
            'udp_session_freed': {
                'type': 'str',
            },
            'no_rev_route': {
                'type': 'str',
            },
            'packet_process_failure': {
                'type': 'str',
            },
            'tcp_session_freed': {
                'type': 'str',
            },
            'other_packet_process': {
                'type': 'str',
            },
            'tcp_fullcone_freed': {
                'type': 'str',
            },
            'outbound_session_freed': {
                'type': 'str',
            },
            'no_class_list_match': {
                'type': 'str',
            },
            'packet_standby_drop': {
                'type': 'str',
            }
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'tcp_packet_process', 'udp_packet_process',
                    'other_packet_process', 'packet_inbound_deny',
                    'packet_process_failure', 'outbound_session_created',
                    'outbound_session_freed', 'inbound_session_created',
                    'inbound_session_freed', 'tcp_session_created',
                    'tcp_session_freed', 'udp_session_created',
                    'udp_session_freed', 'other_session_created',
                    'other_session_freed', 'session_creation_failure',
                    'no_fwd_route', 'no_rev_route', 'packet_standby_drop',
                    'tcp_fullcone_created', 'tcp_fullcone_freed',
                    'udp_fullcone_created', 'udp_fullcone_freed',
                    'fullcone_creation_failure', 'eif_process', 'one_arm_drop',
                    'no_class_list_match', 'outbound_session_created_shadow',
                    'outbound_session_freed_shadow',
                    'inbound_session_created_shadow',
                    'inbound_session_freed_shadow',
                    'tcp_session_created_shadow', 'tcp_session_freed_shadow',
                    'udp_session_created_shadow', 'udp_session_freed_shadow',
                    'other_session_created_shadow',
                    'other_session_freed_shadow',
                    'session_creation_failure_shadow', 'bad_session_freed',
                    'ctl_mem_alloc', 'ctl_mem_free',
                    'tcp_fullcone_created_shadow', 'tcp_fullcone_freed_shadow',
                    'udp_fullcone_created_shadow', 'udp_fullcone_freed_shadow',
                    'fullcone_in_del_q', 'fullcone_overflow_eim',
                    'fullcone_overflow_eif', 'fullcone_free_found',
                    'fullcone_free_retry_lookup', 'fullcone_free_not_found',
                    'eif_limit_exceeded', 'eif_disable_drop',
                    'eif_process_failure', 'eif_filtered',
                    'ha_standby_session_created', 'ha_standby_session_eim',
                    'ha_standby_session_eif'
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
    url_base = "/axapi/v3/cgnv6/stateful-firewall/global"

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
    url_base = "/axapi/v3/cgnv6/stateful-firewall/global"

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
