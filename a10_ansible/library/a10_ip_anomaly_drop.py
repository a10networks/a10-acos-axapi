#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_ip_anomaly_drop
description:
    - None
short_description: Configures A10 ip.anomaly-drop
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
    frag:
        description:
        - "None"
        required: False
    out_of_sequence:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    tcp_syn_fin:
        description:
        - "None"
        required: False
    drop_all:
        description:
        - "None"
        required: False
    ping_of_death:
        description:
        - "None"
        required: False
    security_attack:
        description:
        - "Field security_attack"
        required: False
        suboptions:
            security_attack_layer_3:
                description:
                - "None"
            security_attack_layer_4:
                description:
                - "None"
    tcp_no_flag:
        description:
        - "None"
        required: False
    packet_deformity:
        description:
        - "Field packet_deformity"
        required: False
        suboptions:
            packet_deformity_layer_3:
                description:
                - "None"
            packet_deformity_layer_4:
                description:
                - "None"
    zero_window:
        description:
        - "None"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    ip_option:
        description:
        - "None"
        required: False
    land_attack:
        description:
        - "None"
        required: False
    tcp_syn_frag:
        description:
        - "None"
        required: False
    bad_content:
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
AVAILABLE_PROPERTIES = ["bad_content","drop_all","frag","ip_option","land_attack","out_of_sequence","packet_deformity","ping_of_death","sampling_enable","security_attack","tcp_no_flag","tcp_syn_fin","tcp_syn_frag","uuid","zero_window",]

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
        frag=dict(type='bool',),
        out_of_sequence=dict(type='int',),
        uuid=dict(type='str',),
        tcp_syn_fin=dict(type='bool',),
        drop_all=dict(type='bool',),
        ping_of_death=dict(type='bool',),
        security_attack=dict(type='dict',security_attack_layer_3=dict(type='bool',),security_attack_layer_4=dict(type='bool',)),
        tcp_no_flag=dict(type='bool',),
        packet_deformity=dict(type='dict',packet_deformity_layer_3=dict(type='bool',),packet_deformity_layer_4=dict(type='bool',)),
        zero_window=dict(type='int',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','land','emp_frg','emp_mic_frg','opt','frg','bad_ip_hdrlen','bad_ip_flg','bad_ip_ttl','no_ip_payload','over_ip_payload','bad_ip_payload_len','bad_ip_frg_offset','csum','pod','bad_tcp_urg_offset','tcp_sht_hdr','tcp_bad_iplen','tcp_null_frg','tcp_null_scan','tcp_syn_fin','tcp_xmas','tcp_xmas_scan','tcp_syn_frg','tcp_frg_hdr','tcp_bad_csum','udp_srt_hdr','udp_bad_len','udp_kerb_frg','udp_port_lb','udp_bad_csum','runt_ip_hdr','runt_tcp_udp_hdr','ipip_tnl_msmtch','tcp_opt_err','ipip_tnl_err','vxlan_err','nvgre_err','gre_pptp_err'])),
        ip_option=dict(type='bool',),
        land_attack=dict(type='bool',),
        tcp_syn_frag=dict(type='bool',),
        bad_content=dict(type='int',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ip/anomaly-drop"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ip/anomaly-drop"
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
    payload = build_json("anomaly-drop", module)
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
    payload = build_json("anomaly-drop", module)
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