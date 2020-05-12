#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_so_counters
description:
    - Show scaleout statistics
short_description: Configures A10 so-counters
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
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
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
                - "'all'= all; 'so_pkts_conn_in'= Total packets processed for an established connection; 'so_pkts_conn_redirect'= Total packets redirected for an established connection; 'so_pkts_dropped'= Total packets dropped; 'so_pkts_errors'= Total packet errors; 'so_pkts_in'= Total packets in-coming; 'so_pkts_new_conn_in'= Total packets processed for a new connection; 'so_pkts_new_conn_redirect'= Total packets redirected for a new connection; 'so_pkts_out'= Total packets sent out; 'so_pkts_redirect'= Total packets redirected; 'so_pkts_conn_sync_fail'= Total connection sync failures; 'so_pkts_nat_reserve_fail'= Total NAT reserve failures; 'so_pkts_nat_release_fail'= Total NAT release failures; 'so_pkts_conn_l7_sync'= Total L7 connection syncs; 'so_pkts_conn_l4_sync'= Total L4 connection syncs; 'so_pkts_conn_nat_sync'= Total NAT connection syncs; 'so_pkts_conn_xparent_fw_sync'= Total Xparent FW connection syncs; 'so_pkts_redirect_conn_aged_out'= Total redirect conns aged out; 'so_pkts_traffic_map_not_found_drop'= Traffic MAP Not Found Drop; 'so_pkts_scaleout_not_active_drop'= Scaleout Not Active Drop; 'so_pkts_dest_mac_mistmatch_drop'= Destination MAC Mistmatch Drop; 'so_pkts_l2redirect_interface_not_up'= L2redirect Intf is not UP; 'so_fw_internal_rule_count'= FW internal rule count; 'so_pkts_redirect_table_error'= Redirect Table Error; 'so_pkts_mac_zero_drop'= MAC Address zero Drop; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            so_pkts_conn_l7_sync:
                description:
                - "Total L7 connection syncs"
            so_pkts_traffic_map_not_found_drop:
                description:
                - "Traffic MAP Not Found Drop"
            so_pkts_dropped:
                description:
                - "Total packets dropped"
            so_pkts_conn_xparent_fw_sync:
                description:
                - "Total Xparent FW connection syncs"
            so_pkts_in:
                description:
                - "Total packets in-coming"
            so_pkts_errors:
                description:
                - "Total packet errors"
            so_pkts_conn_sync_fail:
                description:
                - "Total connection sync failures"
            so_pkts_redirect_table_error:
                description:
                - "Redirect Table Error"
            so_pkts_conn_nat_sync:
                description:
                - "Total NAT connection syncs"
            so_fw_internal_rule_count:
                description:
                - "FW internal rule count"
            so_pkts_dest_mac_mistmatch_drop:
                description:
                - "Destination MAC Mistmatch Drop"
            so_pkts_l2redirect_interface_not_up:
                description:
                - "L2redirect Intf is not UP"
            so_pkts_conn_in:
                description:
                - "Total packets processed for an established connection"
            so_pkts_scaleout_not_active_drop:
                description:
                - "Scaleout Not Active Drop"
            so_pkts_conn_redirect:
                description:
                - "Total packets redirected for an established connection"
            so_pkts_redirect_conn_aged_out:
                description:
                - "Total redirect conns aged out"
            so_pkts_nat_reserve_fail:
                description:
                - "Total NAT reserve failures"
            so_pkts_redirect:
                description:
                - "Total packets redirected"
            so_pkts_mac_zero_drop:
                description:
                - "MAC Address zero Drop"
            so_pkts_out:
                description:
                - "Total packets sent out"
            so_pkts_new_conn_in:
                description:
                - "Total packets processed for a new connection"
            so_pkts_nat_release_fail:
                description:
                - "Total NAT release failures"
            so_pkts_new_conn_redirect:
                description:
                - "Total packets redirected for a new connection"
            so_pkts_conn_l4_sync:
                description:
                - "Total L4 connection syncs"
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
AVAILABLE_PROPERTIES = ["sampling_enable","stats","uuid",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'so_pkts_conn_in', 'so_pkts_conn_redirect', 'so_pkts_dropped', 'so_pkts_errors', 'so_pkts_in', 'so_pkts_new_conn_in', 'so_pkts_new_conn_redirect', 'so_pkts_out', 'so_pkts_redirect', 'so_pkts_conn_sync_fail', 'so_pkts_nat_reserve_fail', 'so_pkts_nat_release_fail', 'so_pkts_conn_l7_sync', 'so_pkts_conn_l4_sync', 'so_pkts_conn_nat_sync', 'so_pkts_conn_xparent_fw_sync', 'so_pkts_redirect_conn_aged_out', 'so_pkts_traffic_map_not_found_drop', 'so_pkts_scaleout_not_active_drop', 'so_pkts_dest_mac_mistmatch_drop', 'so_pkts_l2redirect_interface_not_up', 'so_fw_internal_rule_count', 'so_pkts_redirect_table_error', 'so_pkts_mac_zero_drop'])),
        stats=dict(type='dict', so_pkts_conn_l7_sync=dict(type='str', ), so_pkts_traffic_map_not_found_drop=dict(type='str', ), so_pkts_dropped=dict(type='str', ), so_pkts_conn_xparent_fw_sync=dict(type='str', ), so_pkts_in=dict(type='str', ), so_pkts_errors=dict(type='str', ), so_pkts_conn_sync_fail=dict(type='str', ), so_pkts_redirect_table_error=dict(type='str', ), so_pkts_conn_nat_sync=dict(type='str', ), so_fw_internal_rule_count=dict(type='str', ), so_pkts_dest_mac_mistmatch_drop=dict(type='str', ), so_pkts_l2redirect_interface_not_up=dict(type='str', ), so_pkts_conn_in=dict(type='str', ), so_pkts_scaleout_not_active_drop=dict(type='str', ), so_pkts_conn_redirect=dict(type='str', ), so_pkts_redirect_conn_aged_out=dict(type='str', ), so_pkts_nat_reserve_fail=dict(type='str', ), so_pkts_redirect=dict(type='str', ), so_pkts_mac_zero_drop=dict(type='str', ), so_pkts_out=dict(type='str', ), so_pkts_new_conn_in=dict(type='str', ), so_pkts_nat_release_fail=dict(type='str', ), so_pkts_new_conn_redirect=dict(type='str', ), so_pkts_conn_l4_sync=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/so-counters"

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
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/so-counters"

    f_dict = {}

    return url_base.format(**f_dict)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
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
        for k, v in payload["so-counters"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["so-counters"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["so-counters"][k] = v
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
    payload = build_json("so-counters", module)
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
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    if state == 'present':
        result = present(module, result, existing_config)

    elif state == 'absent':
        result = absent(module, result, existing_config)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()