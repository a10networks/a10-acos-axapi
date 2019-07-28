#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
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
        - present
        - absent
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    partition:
        description:
        - Destination/target partition for object/command
    respond_to_user_mac:
        description:
        - "Use the user's source MAC for the next hop rather than the routing table (default= off)"
        required: False
    stateful_firewall_value:
        description:
        - "'enable'= Enable stateful firewall; "
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'tcp_packet_process'= TCP Packet Process; 'udp_packet_process'= UDP Packet Process; 'other_packet_process'= Other Packet Process; 'packet_inbound_deny'= Inbound Packet Denied; 'packet_process_failure'= Packet Error Drop; 'outbound_session_created'= Outbound Session Created; 'outbound_session_freed'= Outbound Session Freed; 'inbound_session_created'= Inbound Session Created; 'inbound_session_freed'= Inbound Session Freed; 'tcp_session_created'= TCP Session Created; 'tcp_session_freed'= TCP Session Freed; 'udp_session_created'= UDP Session Created; 'udp_session_freed'= UDP Session Freed; 'other_session_created'= Other Session Created; 'other_session_freed'= Other Session Freed; 'session_creation_failure'= Session Creation Failure; 'no_fwd_route'= No Forward Route; 'no_rev_route'= No Reverse Route; 'packet_standby_drop'= Standby Drop; 'tcp_fullcone_created'= TCP Full-cone Created; 'tcp_fullcone_freed'= TCP Full-cone Freed; 'udp_fullcone_created'= UDP Full-cone Created; 'udp_fullcone_freed'= UDP Full-cone Freed; 'fullcone_creation_failure'= Full-Cone Creation Failure; 'eif_process'= Endpnt-Independent Filter Matched; 'one_arm_drop'= One-Arm Drop; 'no_class_list_match'= No Class-List Match Drop; 'outbound_session_created_shadow'= Outbound Session Created Shadow; 'outbound_session_freed_shadow'= Outbound Session Freed Shadow; 'inbound_session_created_shadow'= Inbound Session Created Shadow; 'inbound_session_freed_shadow'= Inbound Session Freed Shadow; 'tcp_session_created_shadow'= TCP Session Created Shadow; 'tcp_session_freed_shadow'= TCP Session Freed Shadow; 'udp_session_created_shadow'= UDP Session Created Shadow; 'udp_session_freed_shadow'= UDP Session Freed Shadow; 'other_session_created_shadow'= Other Session Created Shadow; 'other_session_freed_shadow'= Other Session Freed Shadow; 'session_creation_failure_shadow'= Session Creation Failure Shadow; 'bad_session_freed'= Bad Session Proto on Free; 'ctl_mem_alloc'= Memory Alloc; 'ctl_mem_free'= Memory Free; 'tcp_fullcone_created_shadow'= TCP Full-cone Created Shadow; 'tcp_fullcone_freed_shadow'= TCP Full-cone Freed Shadow; 'udp_fullcone_created_shadow'= UDP Full-cone Created Shadow; 'udp_fullcone_freed_shadow'= UDP Full-cone Freed Shadow; 'fullcone_in_del_q'= Full-cone Found in Delete Queue; 'fullcone_overflow_eim'= EIM Overflow; 'fullcone_overflow_eif'= EIF Overflow; 'fullcone_free_found'= Full-cone Free Found From Conn; 'fullcone_free_retry_lookup'= Full-cone Retry Look-up; 'fullcone_free_not_found'= Full-cone Free Not Found; 'eif_limit_exceeded'= EIF Limit Exceeded; 'eif_disable_drop'= EIF Disable Drop; 'eif_process_failure'= EIF Process Failure; 'eif_filtered'= EIF Filtered; 'ha_standby_session_created'= HA Standby Session Created; 'ha_standby_session_eim'= HA Standby Session EIM; 'ha_standby_session_eif'= HA Standby Session EIF; "
    uuid:
        description:
        - "uuid of the object"
        required: False

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["respond_to_user_mac","sampling_enable","stateful_firewall_value","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        respond_to_user_mac=dict(type='bool',),
        stateful_firewall_value=dict(type='str',choices=['enable']),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','tcp_packet_process','udp_packet_process','other_packet_process','packet_inbound_deny','packet_process_failure','outbound_session_created','outbound_session_freed','inbound_session_created','inbound_session_freed','tcp_session_created','tcp_session_freed','udp_session_created','udp_session_freed','other_session_created','other_session_freed','session_creation_failure','no_fwd_route','no_rev_route','packet_standby_drop','tcp_fullcone_created','tcp_fullcone_freed','udp_fullcone_created','udp_fullcone_freed','fullcone_creation_failure','eif_process','one_arm_drop','no_class_list_match','outbound_session_created_shadow','outbound_session_freed_shadow','inbound_session_created_shadow','inbound_session_freed_shadow','tcp_session_created_shadow','tcp_session_freed_shadow','udp_session_created_shadow','udp_session_freed_shadow','other_session_created_shadow','other_session_freed_shadow','session_creation_failure_shadow','bad_session_freed','ctl_mem_alloc','ctl_mem_free','tcp_fullcone_created_shadow','tcp_fullcone_freed_shadow','udp_fullcone_created_shadow','udp_fullcone_freed_shadow','fullcone_in_del_q','fullcone_overflow_eim','fullcone_overflow_eif','fullcone_free_found','fullcone_free_retry_lookup','fullcone_free_not_found','eif_limit_exceeded','eif_disable_drop','eif_process_failure','eif_filtered','ha_standby_session_created','ha_standby_session_eim','ha_standby_session_eif'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/stateful-firewall/global"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/stateful-firewall/global"

    f_dict = {}

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
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

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
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

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("global", module)
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.Exists:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
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

def update(module, result, existing_config):
    payload = build_json("global", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("global", module)
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

    result = dict(
        changed=False,
        original_message="",
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    
    partition = module.params["partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if partition:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()