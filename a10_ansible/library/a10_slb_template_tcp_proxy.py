#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_tcp_proxy
description:
    - None
short_description: Configures A10 slb.template.tcp-proxy
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
    qos:
        description:
        - "None"
        required: False
    init_cwnd:
        description:
        - "None"
        required: False
    idle_timeout:
        description:
        - "None"
        required: False
    fin_timeout:
        description:
        - "None"
        required: False
    half_open_idle_timeout:
        description:
        - "None"
        required: False
    reno:
        description:
        - "None"
        required: False
    down:
        description:
        - "None"
        required: False
    server_down_action:
        description:
        - "None"
        required: False
    timewait:
        description:
        - "None"
        required: False
    dynamic_buffer_allocation:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    disable_sack:
        description:
        - "None"
        required: False
    alive_if_active:
        description:
        - "None"
        required: False
    mss:
        description:
        - "None"
        required: False
    keepalive_interval:
        description:
        - "None"
        required: False
    retransmit_retries:
        description:
        - "None"
        required: False
    insert_client_ip:
        description:
        - "None"
        required: False
    transmit_buffer:
        description:
        - "None"
        required: False
    nagle:
        description:
        - "None"
        required: False
    force_delete_timeout_100ms:
        description:
        - "None"
        required: False
    initial_window_size:
        description:
        - "None"
        required: False
    keepalive_probes:
        description:
        - "None"
        required: False
    ack_aggressiveness:
        description:
        - "None"
        required: False
    backend_wscale:
        description:
        - "None"
        required: False
    disable:
        description:
        - "None"
        required: False
    reset_rev:
        description:
        - "None"
        required: False
    disable_window_scale:
        description:
        - "None"
        required: False
    receive_buffer:
        description:
        - "None"
        required: False
    del_session_on_server_down:
        description:
        - "None"
        required: False
    name:
        description:
        - "None"
        required: True
    reset_fwd:
        description:
        - "None"
        required: False
    disable_tcp_timestamps:
        description:
        - "None"
        required: False
    syn_retries:
        description:
        - "None"
        required: False
    force_delete_timeout:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    invalid_rate_limit:
        description:
        - "None"
        required: False
    half_close_idle_timeout:
        description:
        - "None"
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
AVAILABLE_PROPERTIES = ["ack_aggressiveness","alive_if_active","backend_wscale","del_session_on_server_down","disable","disable_sack","disable_tcp_timestamps","disable_window_scale","down","dynamic_buffer_allocation","fin_timeout","force_delete_timeout","force_delete_timeout_100ms","half_close_idle_timeout","half_open_idle_timeout","idle_timeout","init_cwnd","initial_window_size","insert_client_ip","invalid_rate_limit","keepalive_interval","keepalive_probes","mss","nagle","name","qos","receive_buffer","reno","reset_fwd","reset_rev","retransmit_retries","server_down_action","syn_retries","timewait","transmit_buffer","user_tag","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        qos=dict(type='int',),
        init_cwnd=dict(type='int',),
        idle_timeout=dict(type='int',),
        fin_timeout=dict(type='int',),
        half_open_idle_timeout=dict(type='int',),
        reno=dict(type='bool',),
        down=dict(type='bool',),
        server_down_action=dict(type='str',choices=['FIN','RST']),
        timewait=dict(type='int',),
        dynamic_buffer_allocation=dict(type='bool',),
        uuid=dict(type='str',),
        disable_sack=dict(type='bool',),
        alive_if_active=dict(type='bool',),
        mss=dict(type='int',),
        keepalive_interval=dict(type='int',),
        retransmit_retries=dict(type='int',),
        insert_client_ip=dict(type='bool',),
        transmit_buffer=dict(type='int',),
        nagle=dict(type='bool',),
        force_delete_timeout_100ms=dict(type='int',),
        initial_window_size=dict(type='int',),
        keepalive_probes=dict(type='int',),
        ack_aggressiveness=dict(type='str',choices=['low','medium','high']),
        backend_wscale=dict(type='int',),
        disable=dict(type='bool',),
        reset_rev=dict(type='bool',),
        disable_window_scale=dict(type='bool',),
        receive_buffer=dict(type='int',),
        del_session_on_server_down=dict(type='bool',),
        name=dict(type='str',required=True,),
        reset_fwd=dict(type='bool',),
        disable_tcp_timestamps=dict(type='bool',),
        syn_retries=dict(type='int',),
        force_delete_timeout=dict(type='int',),
        user_tag=dict(type='str',),
        invalid_rate_limit=dict(type='int',),
        half_close_idle_timeout=dict(type='int',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/tcp-proxy/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/tcp-proxy/{name}"
    f_dict = {}
    f_dict["name"] = module.params["name"]

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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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
    payload = build_json("tcp-proxy", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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
    payload = build_json("tcp-proxy", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
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