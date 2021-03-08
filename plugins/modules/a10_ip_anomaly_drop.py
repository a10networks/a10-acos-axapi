#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ip_anomaly_drop
description:
    - Set IP anomaly drop policy
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
    packet_deformity:
        description:
        - "Field packet_deformity"
        type: dict
        required: False
        suboptions:
            packet_deformity_layer_3:
                description:
                - "drop packets with layer 3 anomaly"
                type: bool
            packet_deformity_layer_4:
                description:
                - "drop packets with layer 4 anomaly"
                type: bool
    security_attack:
        description:
        - "Field security_attack"
        type: dict
        required: False
        suboptions:
            security_attack_layer_3:
                description:
                - "drop packets with layer 3 anomaly"
                type: bool
            security_attack_layer_4:
                description:
                - "drop packets with layer 4 anomaly"
                type: bool
    bad_content:
        description:
        - "bad content threshold (threshold value)"
        type: int
        required: False
    drop_all:
        description:
        - "drop all IP anomaly packets"
        type: bool
        required: False
    frag:
        description:
        - "drop all fragmented packets"
        type: bool
        required: False
    ip_option:
        description:
        - "drop packets with IP options"
        type: bool
        required: False
    land_attack:
        description:
        - "drop IP packets with the same source and destination addresses"
        type: bool
        required: False
    out_of_sequence:
        description:
        - "out of sequence packet threshold (threshold value)"
        type: int
        required: False
    ping_of_death:
        description:
        - "drop oversize ICMP packets"
        type: bool
        required: False
    tcp_no_flag:
        description:
        - "drop TCP packets with no flag"
        type: bool
        required: False
    tcp_syn_fin:
        description:
        - "drop TCP packets with both syn and fin flags set"
        type: bool
        required: False
    tcp_syn_frag:
        description:
        - "drop fragmented TCP packets with syn flag set"
        type: bool
        required: False
    zero_window:
        description:
        - "zero window size threshold (threshold value)"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'land'= land; 'emp_frg'= emp_frg; 'emp_mic_frg'= emp_mic_frg;
          'opt'= opt; 'frg'= frg; 'bad_ip_hdrlen'= bad_ip_hdrlen; 'bad_ip_flg'=
          bad_ip_flg; 'bad_ip_ttl'= bad_ip_ttl; 'no_ip_payload'= no_ip_payload;
          'over_ip_payload'= over_ip_payload; 'bad_ip_payload_len'= bad_ip_payload_len;
          'bad_ip_frg_offset'= bad_ip_frg_offset; 'csum'= csum; 'pod'= pod;
          'bad_tcp_urg_offset'= bad_tcp_urg_offset; 'tcp_sht_hdr'= tcp_sht_hdr;
          'tcp_bad_iplen'= tcp_bad_iplen; 'tcp_null_frg'= tcp_null_frg; 'tcp_null_scan'=
          tcp_null_scan; 'tcp_syn_fin'= tcp_syn_fin; 'tcp_xmas'= tcp_xmas;
          'tcp_xmas_scan'= tcp_xmas_scan; 'tcp_syn_frg'= tcp_syn_frg; 'tcp_frg_hdr'=
          tcp_frg_hdr; 'tcp_bad_csum'= tcp_bad_csum; 'udp_srt_hdr'= udp_srt_hdr;
          'udp_bad_len'= udp_bad_len; 'udp_kerb_frg'= udp_kerb_frg; 'udp_port_lb'=
          udp_port_lb; 'udp_bad_csum'= udp_bad_csum; 'runt_ip_hdr'= runt_ip_hdr;
          'runt_tcp_udp_hdr'= runt_tcp_udp_hdr; 'ipip_tnl_msmtch'= ipip_tnl_msmtch;
          'tcp_opt_err'= tcp_opt_err; 'ipip_tnl_err'= ipip_tnl_err; 'vxlan_err'=
          vxlan_err; 'nvgre_err'= nvgre_err; 'gre_pptp_err'= gre_pptp_err;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            land:
                description:
                - "Field land"
                type: str
            emp_frg:
                description:
                - "Field emp_frg"
                type: str
            emp_mic_frg:
                description:
                - "Field emp_mic_frg"
                type: str
            opt:
                description:
                - "Field opt"
                type: str
            frg:
                description:
                - "Field frg"
                type: str
            bad_ip_hdrlen:
                description:
                - "Field bad_ip_hdrlen"
                type: str
            bad_ip_flg:
                description:
                - "Field bad_ip_flg"
                type: str
            bad_ip_ttl:
                description:
                - "Field bad_ip_ttl"
                type: str
            no_ip_payload:
                description:
                - "Field no_ip_payload"
                type: str
            over_ip_payload:
                description:
                - "Field over_ip_payload"
                type: str
            bad_ip_payload_len:
                description:
                - "Field bad_ip_payload_len"
                type: str
            bad_ip_frg_offset:
                description:
                - "Field bad_ip_frg_offset"
                type: str
            csum:
                description:
                - "Field csum"
                type: str
            pod:
                description:
                - "Field pod"
                type: str
            bad_tcp_urg_offset:
                description:
                - "Field bad_tcp_urg_offset"
                type: str
            tcp_sht_hdr:
                description:
                - "Field tcp_sht_hdr"
                type: str
            tcp_bad_iplen:
                description:
                - "Field tcp_bad_iplen"
                type: str
            tcp_null_frg:
                description:
                - "Field tcp_null_frg"
                type: str
            tcp_null_scan:
                description:
                - "Field tcp_null_scan"
                type: str
            tcp_syn_fin:
                description:
                - "Field tcp_syn_fin"
                type: str
            tcp_xmas:
                description:
                - "Field tcp_xmas"
                type: str
            tcp_xmas_scan:
                description:
                - "Field tcp_xmas_scan"
                type: str
            tcp_syn_frg:
                description:
                - "Field tcp_syn_frg"
                type: str
            tcp_frg_hdr:
                description:
                - "Field tcp_frg_hdr"
                type: str
            tcp_bad_csum:
                description:
                - "Field tcp_bad_csum"
                type: str
            udp_srt_hdr:
                description:
                - "Field udp_srt_hdr"
                type: str
            udp_bad_len:
                description:
                - "Field udp_bad_len"
                type: str
            udp_kerb_frg:
                description:
                - "Field udp_kerb_frg"
                type: str
            udp_port_lb:
                description:
                - "Field udp_port_lb"
                type: str
            udp_bad_csum:
                description:
                - "Field udp_bad_csum"
                type: str
            runt_ip_hdr:
                description:
                - "Field runt_ip_hdr"
                type: str
            runt_tcp_udp_hdr:
                description:
                - "Field runt_tcp_udp_hdr"
                type: str
            ipip_tnl_msmtch:
                description:
                - "Field ipip_tnl_msmtch"
                type: str
            tcp_opt_err:
                description:
                - "Field tcp_opt_err"
                type: str
            ipip_tnl_err:
                description:
                - "Field ipip_tnl_err"
                type: str
            vxlan_err:
                description:
                - "Field vxlan_err"
                type: str
            nvgre_err:
                description:
                - "Field nvgre_err"
                type: str
            gre_pptp_err:
                description:
                - "Field gre_pptp_err"
                type: str

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
    "bad_content",
    "drop_all",
    "frag",
    "ip_option",
    "land_attack",
    "out_of_sequence",
    "packet_deformity",
    "ping_of_death",
    "sampling_enable",
    "security_attack",
    "stats",
    "tcp_no_flag",
    "tcp_syn_fin",
    "tcp_syn_frag",
    "uuid",
    "zero_window",
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
        'packet_deformity': {
            'type': 'dict',
            'packet_deformity_layer_3': {
                'type': 'bool',
            },
            'packet_deformity_layer_4': {
                'type': 'bool',
            }
        },
        'security_attack': {
            'type': 'dict',
            'security_attack_layer_3': {
                'type': 'bool',
            },
            'security_attack_layer_4': {
                'type': 'bool',
            }
        },
        'bad_content': {
            'type': 'int',
        },
        'drop_all': {
            'type': 'bool',
        },
        'frag': {
            'type': 'bool',
        },
        'ip_option': {
            'type': 'bool',
        },
        'land_attack': {
            'type': 'bool',
        },
        'out_of_sequence': {
            'type': 'int',
        },
        'ping_of_death': {
            'type': 'bool',
        },
        'tcp_no_flag': {
            'type': 'bool',
        },
        'tcp_syn_fin': {
            'type': 'bool',
        },
        'tcp_syn_frag': {
            'type': 'bool',
        },
        'zero_window': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'land', 'emp_frg', 'emp_mic_frg', 'opt', 'frg',
                    'bad_ip_hdrlen', 'bad_ip_flg', 'bad_ip_ttl',
                    'no_ip_payload', 'over_ip_payload', 'bad_ip_payload_len',
                    'bad_ip_frg_offset', 'csum', 'pod', 'bad_tcp_urg_offset',
                    'tcp_sht_hdr', 'tcp_bad_iplen', 'tcp_null_frg',
                    'tcp_null_scan', 'tcp_syn_fin', 'tcp_xmas',
                    'tcp_xmas_scan', 'tcp_syn_frg', 'tcp_frg_hdr',
                    'tcp_bad_csum', 'udp_srt_hdr', 'udp_bad_len',
                    'udp_kerb_frg', 'udp_port_lb', 'udp_bad_csum',
                    'runt_ip_hdr', 'runt_tcp_udp_hdr', 'ipip_tnl_msmtch',
                    'tcp_opt_err', 'ipip_tnl_err', 'vxlan_err', 'nvgre_err',
                    'gre_pptp_err'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'land': {
                'type': 'str',
            },
            'emp_frg': {
                'type': 'str',
            },
            'emp_mic_frg': {
                'type': 'str',
            },
            'opt': {
                'type': 'str',
            },
            'frg': {
                'type': 'str',
            },
            'bad_ip_hdrlen': {
                'type': 'str',
            },
            'bad_ip_flg': {
                'type': 'str',
            },
            'bad_ip_ttl': {
                'type': 'str',
            },
            'no_ip_payload': {
                'type': 'str',
            },
            'over_ip_payload': {
                'type': 'str',
            },
            'bad_ip_payload_len': {
                'type': 'str',
            },
            'bad_ip_frg_offset': {
                'type': 'str',
            },
            'csum': {
                'type': 'str',
            },
            'pod': {
                'type': 'str',
            },
            'bad_tcp_urg_offset': {
                'type': 'str',
            },
            'tcp_sht_hdr': {
                'type': 'str',
            },
            'tcp_bad_iplen': {
                'type': 'str',
            },
            'tcp_null_frg': {
                'type': 'str',
            },
            'tcp_null_scan': {
                'type': 'str',
            },
            'tcp_syn_fin': {
                'type': 'str',
            },
            'tcp_xmas': {
                'type': 'str',
            },
            'tcp_xmas_scan': {
                'type': 'str',
            },
            'tcp_syn_frg': {
                'type': 'str',
            },
            'tcp_frg_hdr': {
                'type': 'str',
            },
            'tcp_bad_csum': {
                'type': 'str',
            },
            'udp_srt_hdr': {
                'type': 'str',
            },
            'udp_bad_len': {
                'type': 'str',
            },
            'udp_kerb_frg': {
                'type': 'str',
            },
            'udp_port_lb': {
                'type': 'str',
            },
            'udp_bad_csum': {
                'type': 'str',
            },
            'runt_ip_hdr': {
                'type': 'str',
            },
            'runt_tcp_udp_hdr': {
                'type': 'str',
            },
            'ipip_tnl_msmtch': {
                'type': 'str',
            },
            'tcp_opt_err': {
                'type': 'str',
            },
            'ipip_tnl_err': {
                'type': 'str',
            },
            'vxlan_err': {
                'type': 'str',
            },
            'nvgre_err': {
                'type': 'str',
            },
            'gre_pptp_err': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ip/anomaly-drop"

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
    url_base = "/axapi/v3/ip/anomaly-drop"

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
        for k, v in payload["anomaly-drop"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["anomaly-drop"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["anomaly-drop"][k] = v
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
    payload = build_json("anomaly-drop", module)
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
