#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_virtual_server_port_stats_http_vport
description:
    - Statistics for the object port
short_description: Configures A10 slb.virtual-server.port.stats.http-vport
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
    protocol:
        description:
        - Key to identify parent object
    port_number:
        description:
        - Key to identify parent object
    virtual_server_name:
        description:
        - Key to identify parent object
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            http_vport:
                description:
                - "Field http_vport"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["stats",]

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
        get_type=dict(type='str', choices=["single", "list"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        stats=dict(type='dict',http_vport=dict(type='dict',jsi_api_no_token=dict(type='str',),REQ_50u=dict(type='str',),http2_control_bytes=dict(type='str',),ws_server_switch=dict(type='str',),REQ_50m=dict(type='str',),status_450=dict(type='str',),http2_reset_received=dict(type='str',),jsi_hash_add_fails=dict(type='str',),jsi_requests=dict(type='str',),ws_handshake_request=dict(type='str',),jsi_api_responses=dict(type='str',),http2_header_bytes=dict(type='str',),status_207=dict(type='str',),status_206=dict(type='str',),status_205=dict(type='str',),status_204=dict(type='str',),status_203=dict(type='str',),status_202=dict(type='str',),status_201=dict(type='str',),status_200=dict(type='str',),jsi_api_no_auth_hdr=dict(type='str',),ws_client_switch=dict(type='str',),status_2xx=dict(type='str',),http2_goaway_received=dict(type='str',),REQ_500u=dict(type='str',),status_4xx=dict(type='str',),total_requests=dict(type='str',),status_3xx=dict(type='str',),REQ_2s=dict(type='str',),stream_closed=dict(type='str',),REQ_100m=dict(type='str',),REQ_5m=dict(type='str',),REQ_100u=dict(type='str',),REQ_5s=dict(type='str',),jsi_hash_lookup_fails=dict(type='str',),REQ_500m=dict(type='str',),header_length_long=dict(type='str',),REQ_20u=dict(type='str',),REQ_200u=dict(type='str',),status_412=dict(type='str',),total_http2_bytes=dict(type='str',),status_411=dict(type='str',),status_306=dict(type='str',),status_307=dict(type='str',),status_304=dict(type='str',),status_305=dict(type='str',),status_302=dict(type='str',),status_303=dict(type='str',),REQ_2m=dict(type='str',),status_301=dict(type='str',),REQ_10u=dict(type='str',),total_http2_conn=dict(type='str',),REQ_10m=dict(type='str',),REQ_200m=dict(type='str',),peak_http2_conn=dict(type='str',),status_510=dict(type='str',),jsi_api_requests=dict(type='str',),status_413=dict(type='str',),status_410=dict(type='str',),http2_reset_sent=dict(type='str',),status_416=dict(type='str',),status_417=dict(type='str',),status_414=dict(type='str',),status_415=dict(type='str',),status_418=dict(type='str',),status_unknown=dict(type='str',),status_100=dict(type='str',),status_101=dict(type='str',),status_102=dict(type='str',),status_103=dict(type='str',),jsi_responses=dict(type='str',),status_300=dict(type='str',),status_424=dict(type='str',),status_508=dict(type='str',),curr_http2_conn=dict(type='str',),ws_handshake_success=dict(type='str',),status_504_ax=dict(type='str',),status_6xx=dict(type='str',),status_5xx=dict(type='str',),http2_data_bytes=dict(type='str',),status_401=dict(type='str',),status_400=dict(type='str',),status_403=dict(type='str',),status_402=dict(type='str',),status_405=dict(type='str',),status_404=dict(type='str',),status_407=dict(type='str',),status_406=dict(type='str',),status_409=dict(type='str',),status_408=dict(type='str',),jsi_skip_not_browser=dict(type='str',),http2_goaway_sent=dict(type='str',),REQ_1m=dict(type='str',),jsi_skip_no_ua=dict(type='str',),REQ_1s=dict(type='str',),status_1xx=dict(type='str',),jsi_pri_requests=dict(type='str',),status_423=dict(type='str',),status_422=dict(type='str',),status_426=dict(type='str',),status_425=dict(type='str',),REQ_20m=dict(type='str',),jsi_skip_no_fi=dict(type='str',),status_509=dict(type='str',),REQ_OVER_5s=dict(type='str',),status_500=dict(type='str',),status_501=dict(type='str',),status_502=dict(type='str',),status_503=dict(type='str',),status_504=dict(type='str',),status_505=dict(type='str',),status_506=dict(type='str',),status_507=dict(type='str',),status_449=dict(type='str',)))
    ))
   
    # Parent keys
    rv.update(dict(
        protocol=dict(type='str', required=True),
        port_number=dict(type='str', required=True),
        virtual_server_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?http_vport=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?http_vport=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

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

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_oper(module)
    return module.client.get(oper_url(module))

def get_stats(module)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["port"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["port"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["port"][k] = v
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
    payload = build_json("port", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
        return result
    else:
        return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("port", module)
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
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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