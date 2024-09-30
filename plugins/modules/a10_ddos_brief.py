#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_brief
description:
    - ddos brief counters
author: A10 Networks
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            ip_rcv:
                description:
                - "IPv4 Received"
                type: str
            ip_sent:
                description:
                - "IPv4 Sent"
                type: str
            ipv6_rcv:
                description:
                - "IPv6 Received"
                type: str
            ipv6_sent:
                description:
                - "IPv6 Sent"
                type: str
            out_no_route:
                description:
                - "IPv4/v6 Out No Route"
                type: str
            not_for_ddos:
                description:
                - "Not For DDOS"
                type: str
            instateless:
                description:
                - "Stateless Packets Received"
                type: str
            intcp:
                description:
                - "TCP Total Packets Received"
                type: str
            inudp:
                description:
                - "UDP Total Packets Received"
                type: str
            inicmp:
                description:
                - "ICMP Total Packets Received"
                type: str
            inother:
                description:
                - "OTHER Total Packets Received"
                type: str
            v4_sess_create:
                description:
                - "IPv4 Session Created"
                type: str
            v6_sess_create:
                description:
                - "IPv6 Session Created"
                type: str
            tcp_sess_create:
                description:
                - "TCP Sessions Created"
                type: str
            udp_sess_create:
                description:
                - "UDP Sessions Created"
                type: str
            sess_aged_out:
                description:
                - "Session Aged Out"
                type: str
            tcp_total_drop:
                description:
                - "TCP Total Packets Dropped"
                type: str
            tcp_dst_drop:
                description:
                - "TCP Dst Packets Dropped"
                type: str
            tcp_src_drop:
                description:
                - "TCP Src Packets Dropped"
                type: str
            tcp_src_dst_drop:
                description:
                - "TCP SrcDst Packets Dropped"
                type: str
            udp_total_drop:
                description:
                - "UDP Total Packets Dropped"
                type: str
            udp_dst_drop:
                description:
                - "UDP Dst Packets Dropped"
                type: str
            udp_src_drop:
                description:
                - "UDP Src Packets Dropped"
                type: str
            udp_src_dst_drop:
                description:
                - "UDP SrcDst Packets Dropped"
                type: str
            icmp_total_drop:
                description:
                - "ICMP Total Packets Dropped"
                type: str
            icmp_dst_drop:
                description:
                - "ICMP Dst Packets Dropped"
                type: str
            icmp_src_drop:
                description:
                - "ICMP Src Packets Dropped"
                type: str
            icmp_src_dst_drop:
                description:
                - "ICMP SrcDst Packets Dropped"
                type: str
            other_total_drop:
                description:
                - "OTHER Total Packets Dropped"
                type: str
            other_dst_drop:
                description:
                - "OTHER Dst Packets Dropped"
                type: str
            other_src_drop:
                description:
                - "OTHER Src Packets Dropped"
                type: str
            other_src_dst_drop:
                description:
                - "OTHER SrcDst Packets Dropped"
                type: str
            frag_rcvd:
                description:
                - "Fragmented Packets Received"
                type: str
            frag_drop:
                description:
                - "Fragmented Packets Dropped"
                type: str
            dst_port_undef_drop:
                description:
                - "Dst Port Undefined Dropped"
                type: str
            dst_port_exceed_drop_any:
                description:
                - "Dst Port Exceed Dropped"
                type: str
            dst_ipproto_bl:
                description:
                - "Dst IP-Proto Blacklist Packets Dropped"
                type: str
            dst_port_bl:
                description:
                - "Dst Port Blacklist Packets Dropped"
                type: str
            dst_sport_bl:
                description:
                - "Dst SrcPort Blacklist Packets Dropped"
                type: str
            dst_sport_exceed_drop_any:
                description:
                - "Dst SrcPort Exceed Dropped"
                type: str
            dst_ipproto_rcvd:
                description:
                - "Dst IP-Proto Total Packets Received"
                type: str
            dst_ipproto_drop:
                description:
                - "Dst IP-Proto Total Packets Dropped"
                type: str
            dst_ipproto_exceed_drop_any:
                description:
                - "Dst IP-Proto Exceed Dropped"
                type: str
            src_ip_bypass:
                description:
                - "Src IP Bypass"
                type: str
            dst_ingress_bytes:
                description:
                - "Inbound Bytes Received"
                type: str
            dst_egress_bytes:
                description:
                - "Outbound Bytes Received"
                type: str
            dst_ingress_packets:
                description:
                - "Inbound Packets Received"
                type: str
            dst_egress_packets:
                description:
                - "Outbound Packets Received"
                type: str
            dst_ip_bypass:
                description:
                - "Dst IP Bypass"
                type: str
            dst_blackhole_inject:
                description:
                - "Dst Blackhole Injected"
                type: str
            dst_blackhole_withdraw:
                description:
                - "Dst Blackhole Withdrawn"
                type: str
            tcp_total_bytes_rcv:
                description:
                - "TCP Total Bytes Received"
                type: str
            tcp_total_bytes_drop:
                description:
                - "TCP Total Bytes Dropped"
                type: str
            udp_total_bytes_rcv:
                description:
                - "UDP Total Bytes Received"
                type: str
            udp_total_bytes_drop:
                description:
                - "UDP Total Bytes Dropped"
                type: str
            icmp_total_bytes_rcv:
                description:
                - "ICMP Total Bytes Received"
                type: str
            icmp_total_bytes_drop:
                description:
                - "ICMP Total Bytes Dropped"
                type: str
            other_total_bytes_rcv:
                description:
                - "OTHER Total Bytes Received"
                type: str
            other_total_bytes_drop:
                description:
                - "OTHER Total Bytes Dropped"
                type: str
            udp_any_exceed:
                description:
                - "UDP Exceeded"
                type: str
            tcp_any_exceed:
                description:
                - "TCP Exceeded"
                type: str
            icmp_any_exceed:
                description:
                - "ICMP Exceeded"
                type: str
            other_any_exceed:
                description:
                - "OTHER Exceeded"
                type: str
            tcp_drop_bl:
                description:
                - "TCP Blacklist Packets Dropped"
                type: str
            udp_drop_bl:
                description:
                - "UDP Blacklist Packets Dropped"
                type: str
            icmp_drop_bl:
                description:
                - "ICMP Blacklisted Packets Dropped"
                type: str
            other_drop_bl:
                description:
                - "OTHER Blacklisted Packets Dropped"
                type: str
            glid_action_encap_send_immed:
                description:
                - "Glid Action Tunnel-encap"
                type: str
            glid_action_encap_send_delay:
                description:
                - "Glid Action Tunnel-encap with Scrub"
                type: str
            dst_hw_drop:
                description:
                - "Dst Default Hardware Packets Dropped"
                type: str
            dst_hw_drop_rule_inserted:
                description:
                - "Dst Default Hardware Drop Rules Inserted"
                type: str
            dst_hw_drop_rule_removed:
                description:
                - "Dst Default Hardware Drop Rules Removed"
                type: str
            src_hw_drop_rule_inserted:
                description:
                - "Src Default Hardware Drop Rules Inserted"
                type: str
            src_hw_drop_rule_removed:
                description:
                - "Src Default Hardware Drop Rules Removed"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["stats", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'uuid': {
            'type': 'str',
            },
        'stats': {
            'type': 'dict',
            'ip_rcv': {
                'type': 'str',
                },
            'ip_sent': {
                'type': 'str',
                },
            'ipv6_rcv': {
                'type': 'str',
                },
            'ipv6_sent': {
                'type': 'str',
                },
            'out_no_route': {
                'type': 'str',
                },
            'not_for_ddos': {
                'type': 'str',
                },
            'instateless': {
                'type': 'str',
                },
            'intcp': {
                'type': 'str',
                },
            'inudp': {
                'type': 'str',
                },
            'inicmp': {
                'type': 'str',
                },
            'inother': {
                'type': 'str',
                },
            'v4_sess_create': {
                'type': 'str',
                },
            'v6_sess_create': {
                'type': 'str',
                },
            'tcp_sess_create': {
                'type': 'str',
                },
            'udp_sess_create': {
                'type': 'str',
                },
            'sess_aged_out': {
                'type': 'str',
                },
            'tcp_total_drop': {
                'type': 'str',
                },
            'tcp_dst_drop': {
                'type': 'str',
                },
            'tcp_src_drop': {
                'type': 'str',
                },
            'tcp_src_dst_drop': {
                'type': 'str',
                },
            'udp_total_drop': {
                'type': 'str',
                },
            'udp_dst_drop': {
                'type': 'str',
                },
            'udp_src_drop': {
                'type': 'str',
                },
            'udp_src_dst_drop': {
                'type': 'str',
                },
            'icmp_total_drop': {
                'type': 'str',
                },
            'icmp_dst_drop': {
                'type': 'str',
                },
            'icmp_src_drop': {
                'type': 'str',
                },
            'icmp_src_dst_drop': {
                'type': 'str',
                },
            'other_total_drop': {
                'type': 'str',
                },
            'other_dst_drop': {
                'type': 'str',
                },
            'other_src_drop': {
                'type': 'str',
                },
            'other_src_dst_drop': {
                'type': 'str',
                },
            'frag_rcvd': {
                'type': 'str',
                },
            'frag_drop': {
                'type': 'str',
                },
            'dst_port_undef_drop': {
                'type': 'str',
                },
            'dst_port_exceed_drop_any': {
                'type': 'str',
                },
            'dst_ipproto_bl': {
                'type': 'str',
                },
            'dst_port_bl': {
                'type': 'str',
                },
            'dst_sport_bl': {
                'type': 'str',
                },
            'dst_sport_exceed_drop_any': {
                'type': 'str',
                },
            'dst_ipproto_rcvd': {
                'type': 'str',
                },
            'dst_ipproto_drop': {
                'type': 'str',
                },
            'dst_ipproto_exceed_drop_any': {
                'type': 'str',
                },
            'src_ip_bypass': {
                'type': 'str',
                },
            'dst_ingress_bytes': {
                'type': 'str',
                },
            'dst_egress_bytes': {
                'type': 'str',
                },
            'dst_ingress_packets': {
                'type': 'str',
                },
            'dst_egress_packets': {
                'type': 'str',
                },
            'dst_ip_bypass': {
                'type': 'str',
                },
            'dst_blackhole_inject': {
                'type': 'str',
                },
            'dst_blackhole_withdraw': {
                'type': 'str',
                },
            'tcp_total_bytes_rcv': {
                'type': 'str',
                },
            'tcp_total_bytes_drop': {
                'type': 'str',
                },
            'udp_total_bytes_rcv': {
                'type': 'str',
                },
            'udp_total_bytes_drop': {
                'type': 'str',
                },
            'icmp_total_bytes_rcv': {
                'type': 'str',
                },
            'icmp_total_bytes_drop': {
                'type': 'str',
                },
            'other_total_bytes_rcv': {
                'type': 'str',
                },
            'other_total_bytes_drop': {
                'type': 'str',
                },
            'udp_any_exceed': {
                'type': 'str',
                },
            'tcp_any_exceed': {
                'type': 'str',
                },
            'icmp_any_exceed': {
                'type': 'str',
                },
            'other_any_exceed': {
                'type': 'str',
                },
            'tcp_drop_bl': {
                'type': 'str',
                },
            'udp_drop_bl': {
                'type': 'str',
                },
            'icmp_drop_bl': {
                'type': 'str',
                },
            'other_drop_bl': {
                'type': 'str',
                },
            'glid_action_encap_send_immed': {
                'type': 'str',
                },
            'glid_action_encap_send_delay': {
                'type': 'str',
                },
            'dst_hw_drop': {
                'type': 'str',
                },
            'dst_hw_drop_rule_inserted': {
                'type': 'str',
                },
            'dst_hw_drop_rule_removed': {
                'type': 'str',
                },
            'src_hw_drop_rule_inserted': {
                'type': 'str',
                },
            'src_hw_drop_rule_removed': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/brief"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/brief"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("brief", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        if state == 'present' or state == 'absent':
            existing_config = api_client.get(module.client, existing_url(module))
            result["axapi_calls"].append(existing_config)
            if existing_config['response_body'] != 'NotFound':
                existing_config = existing_config["response_body"]
            else:
                existing_config = None
        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["brief"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["brief-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["brief"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
