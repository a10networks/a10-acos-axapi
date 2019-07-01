#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_ddos_protection
description:
    - Configure CGNV6 DDoS Protection
short_description: Configures A10 cgnv6.ddos-protection
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
    logging:
        description:
        - "Field logging"
        required: False
        suboptions:
            logging_toggle:
                description:
                - "'enable'= Enable CGNV6 NAT pool DDoS protection logging (default); 'disable'= Disable CGNV6 NAT pool DDoS protection logging; "
    uuid:
        description:
        - "uuid of the object"
        required: False
    zone:
        description:
        - "Disable NAT IP based on DDoS zone name set in BGP"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'l3_entry_added'= L3 Entry Added; 'l3_entry_deleted'= L3 Entry Deleted; 'l3_entry_added_to_bgp'= L3 Entry added to BGP; 'l3_entry_removed_from_bgp'= Entry removed from BGP; 'l3_entry_added_to_hw'= L3 Entry added to HW; 'l3_entry_removed_from_hw'= L3 Entry removed from HW; 'l3_entry_too_many'= L3 Too many entries; 'l3_entry_match_drop'= L3 Entry match drop; 'l3_entry_match_drop_hw'= L3 HW entry match drop; 'l3_entry_drop_max_hw_exceeded'= L3 Entry Drop due to HW Limit Exceeded; 'l4_entry_added'= L4 Entry added; 'l4_entry_deleted'= L4 Entry deleted; 'l4_entry_added_to_hw'= L4 Entry added to HW; 'l4_entry_removed_from_hw'= L4 Entry removed from HW; 'l4_hw_out_of_entries'= HW out of L4 entries; 'l4_entry_match_drop'= L4 Entry match drop; 'l4_entry_match_drop_hw'= L4 HW Entry match drop; 'l4_entry_drop_max_hw_exceeded'= L4 Entry Drop due to HW Limit Exceeded; 'l4_entry_list_alloc'= L4 Entry list alloc; 'l4_entry_list_free'= L4 Entry list free; 'l4_entry_list_alloc_failure'= L4 Entry list alloc failures; 'ip_node_alloc'= Node alloc; 'ip_node_free'= Node free; 'ip_node_alloc_failure'= Node alloc failures; 'ip_port_block_alloc'= Port block alloc; 'ip_port_block_free'= Port block free; 'ip_port_block_alloc_failure'= Port block alloc failure; 'ip_other_block_alloc'= Other block alloc; 'ip_other_block_free'= Other block free; 'ip_other_block_alloc_failure'= Other block alloc failure; 'entry_added_shadow'= Entry added shadow; 'entry_invalidated'= Entry invalidated; 'l3_entry_add_to_bgp_failure'= L3 Entry BGP add failures; 'l3_entry_remove_from_bgp_failure'= L3 entry BGP remove failures; 'l3_entry_add_to_hw_failure'= L3 entry HW add failure; "
    toggle:
        description:
        - "'enable'= Enable CGNV6 NAT pool DDoS protection (default); 'disable'= Disable CGNV6 NAT pool DDoS protection; "
        required: False
    max_hw_entries:
        description:
        - "Configure maximum HW entries"
        required: False
    packets_per_second:
        description:
        - "Field packets_per_second"
        required: False
        suboptions:
            udp:
                description:
                - "Configure packets-per-second threshold per UDP port (default= 3000)"
            ip:
                description:
                - "Configure packets-per-second threshold per IP(default 3000000)"
            tcp:
                description:
                - "Configure packets-per-second threshold per TCP port (default= 3000)"
            other:
                description:
                - "Configure packets-per-second threshold for other L4 protocols(default 10000)"
            action:
                description:
                - "Field action"
            include_existing_session:
                description:
                - "Count traffic associated with existing session into the packets-per-second (Default= Disabled)"

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["logging","max_hw_entries","packets_per_second","sampling_enable","toggle","uuid","zone",]

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
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        logging=dict(type='dict',logging_toggle=dict(type='str',choices=['enable','disable'])),
        uuid=dict(type='str',),
        zone=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','l3_entry_added','l3_entry_deleted','l3_entry_added_to_bgp','l3_entry_removed_from_bgp','l3_entry_added_to_hw','l3_entry_removed_from_hw','l3_entry_too_many','l3_entry_match_drop','l3_entry_match_drop_hw','l3_entry_drop_max_hw_exceeded','l4_entry_added','l4_entry_deleted','l4_entry_added_to_hw','l4_entry_removed_from_hw','l4_hw_out_of_entries','l4_entry_match_drop','l4_entry_match_drop_hw','l4_entry_drop_max_hw_exceeded','l4_entry_list_alloc','l4_entry_list_free','l4_entry_list_alloc_failure','ip_node_alloc','ip_node_free','ip_node_alloc_failure','ip_port_block_alloc','ip_port_block_free','ip_port_block_alloc_failure','ip_other_block_alloc','ip_other_block_free','ip_other_block_alloc_failure','entry_added_shadow','entry_invalidated','l3_entry_add_to_bgp_failure','l3_entry_remove_from_bgp_failure','l3_entry_add_to_hw_failure'])),
        toggle=dict(type='str',choices=['enable','disable']),
        max_hw_entries=dict(type='int',),
        packets_per_second=dict(type='dict',udp=dict(type='int',),ip=dict(type='int',),tcp=dict(type='int',),other=dict(type='int',),action=dict(type='dict',route_map=dict(type='str',),timer_multiply_max=dict(type='int',),action_type=dict(type='str',choices=['log','drop','redistribute-route']),expiration=dict(type='int',)),include_existing_session=dict(type='bool',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/ddos-protection"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/ddos-protection"

    f_dict = {}

    return url_base.format(**f_dict)

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

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

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("ddos-protection", module)
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
    payload = build_json("ddos-protection", module)
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
    payload = build_json("ddos-protection", module)
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
        message="",
        result={}
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
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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