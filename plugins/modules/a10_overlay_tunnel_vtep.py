#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_overlay_tunnel_vtep
description:
    - Virtual Tunnel end point Configuration
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
    id:
        description:
        - "VTEP Identifier"
        type: int
        required: True
    encap:
        description:
        - "'ip-encap'= Tunnel encapsulation type is IP; 'gre'= Tunnel encapsulation type
          is GRE; 'nvgre'= Tunnel Encapsulation Type is NVGRE; 'vxlan'= Tunnel
          Encapsulation Type is VXLAN;"
        type: str
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'cfg_err_count'= Config errors; 'flooded_pkt_count'= Flooded packet
          count; 'encap_unresolved_count'= Encap unresolved failures;
          'unknown_encap_rx_pkt'= Encap miss rx pkts; 'unknown_encap_tx_pkt'= Encap miss
          tx pkts; 'arp_req_sent'= Arp request sent; 'vtep_host_learned'= Hosts learned;
          'vtep_host_learn_error'= Host learn error; 'invalid_lif_rx'= Invalid Lif pkts
          in; 'invalid_lif_tx'= Invalid Lif pkts out; 'unknown_vtep_tx'= Vtep unknown tx;
          'unknown_vtep_rx'= Vtep Unkown rx; 'unhandled_pkt_rx'= Unhandled packets in;
          'unhandled_pkt_tx'= Unhandled packets out; 'total_pkts_rx'= Total packets out;
          'total_bytes_rx'= Total packet bytes in; 'unicast_pkt_rx'= Total unicast
          packets in; 'bcast_pkt_rx'= Total broadcast packets in; 'mcast_pkt_rx'= Total
          multicast packets in; 'dropped_pkt_rx'= Dropped received packets;
          'encap_miss_pkts_rx'= Encap missed in received packets; 'bad_chksum_pks_rx'=
          Bad checksum in received packets; 'requeue_pkts_in'= Requeued packets in;
          'pkts_out'= Packets out; 'total_bytes_tx'= Packet bytes out; 'unicast_pkt_tx'=
          Unicast packets out; 'bcast_pkt_tx'= Broadcast packets out; 'mcast_pkt_tx'=
          Multicast packets out; 'dropped_pkts_tx'= Dropped packets out; 'large_pkts_rx'=
          Too large packets in; 'dot1q_pkts_rx'= Dot1q packets in; 'frag_pkts_tx'= Frag
          packets out; 'reassembled_pkts_rx'= Reassembled packets in;
          'bad_inner_ipv4_len_rx'= bad inner ipv4 packet len; 'bad_inner_ipv6_len_rx'=
          Bad inner ipv6 packet len; 'frag_drop_pkts_tx'= Frag dropped packets out;
          'lif_un_init_rx'= Lif uninitialized packets in;"
                type: str
    local_ip_address:
        description:
        - "Field local_ip_address"
        type: dict
        required: False
        suboptions:
            ip_address:
                description:
                - "Source Tunnel End Point IPv4 address"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            vni_list:
                description:
                - "Field vni_list"
                type: list
    local_ipv6_address:
        description:
        - "Field local_ipv6_address"
        type: dict
        required: False
        suboptions:
            ipv6_address:
                description:
                - "Source Tunnel End Point IPv6 address"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            vni_list:
                description:
                - "Field vni_list"
                type: list
    remote_ip_address_list:
        description:
        - "Field remote_ip_address_list"
        type: list
        required: False
        suboptions:
            ip_address:
                description:
                - "IP Address of the remote VTEP"
                type: str
            class_list:
                description:
                - "Name of the class-list"
                type: str
            encap:
                description:
                - "'nvgre'= Tunnel Encapsulation Type is NVGRE; 'vxlan'= Tunnel Encapsulation Type
          is VXLAN;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            use_lif:
                description:
                - "Field use_lif"
                type: dict
            gre_keepalive:
                description:
                - "Field gre_keepalive"
                type: dict
            use_gre_key:
                description:
                - "Field use_gre_key"
                type: dict
            vni_list:
                description:
                - "Field vni_list"
                type: list
    remote_ipv6_address_list:
        description:
        - "Field remote_ipv6_address_list"
        type: list
        required: False
        suboptions:
            ipv6_address:
                description:
                - "IPv6 Address of the remote VTEP"
                type: str
            class_list:
                description:
                - "Name of the class-list"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            use_lif:
                description:
                - "Field use_lif"
                type: dict
            vni_list:
                description:
                - "Field vni_list"
                type: list
    host_list:
        description:
        - "Field host_list"
        type: list
        required: False
        suboptions:
            ip_addr:
                description:
                - "IPv4 address of the overlay host"
                type: str
            ipv6_addr:
                description:
                - "IPv6 address of the overlay host"
                type: str
            overlay_mac_addr:
                description:
                - "MAC Address of the overlay host"
                type: str
            vni:
                description:
                - " Configure the segment id ( VNI of the remote host)"
                type: int
            remote_vtep:
                description:
                - "Configure the VTEP IP address (IPv4 address of the VTEP for the remote host)"
                type: str
            remote_ipv6_vtep:
                description:
                - "Configure the VTEP IPv6 address (IPv6 address of the VTEP for the remote host)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            cfg_err_count:
                description:
                - "Config errors"
                type: str
            flooded_pkt_count:
                description:
                - "Flooded packet count"
                type: str
            encap_unresolved_count:
                description:
                - "Encap unresolved failures"
                type: str
            unknown_encap_rx_pkt:
                description:
                - "Encap miss rx pkts"
                type: str
            unknown_encap_tx_pkt:
                description:
                - "Encap miss tx pkts"
                type: str
            arp_req_sent:
                description:
                - "Arp request sent"
                type: str
            vtep_host_learned:
                description:
                - "Hosts learned"
                type: str
            vtep_host_learn_error:
                description:
                - "Host learn error"
                type: str
            invalid_lif_rx:
                description:
                - "Invalid Lif pkts in"
                type: str
            invalid_lif_tx:
                description:
                - "Invalid Lif pkts out"
                type: str
            unknown_vtep_tx:
                description:
                - "Vtep unknown tx"
                type: str
            unknown_vtep_rx:
                description:
                - "Vtep Unkown rx"
                type: str
            unhandled_pkt_rx:
                description:
                - "Unhandled packets in"
                type: str
            unhandled_pkt_tx:
                description:
                - "Unhandled packets out"
                type: str
            total_pkts_rx:
                description:
                - "Total packets out"
                type: str
            total_bytes_rx:
                description:
                - "Total packet bytes in"
                type: str
            unicast_pkt_rx:
                description:
                - "Total unicast packets in"
                type: str
            bcast_pkt_rx:
                description:
                - "Total broadcast packets in"
                type: str
            mcast_pkt_rx:
                description:
                - "Total multicast packets in"
                type: str
            dropped_pkt_rx:
                description:
                - "Dropped received packets"
                type: str
            encap_miss_pkts_rx:
                description:
                - "Encap missed in received packets"
                type: str
            bad_chksum_pks_rx:
                description:
                - "Bad checksum in received packets"
                type: str
            requeue_pkts_in:
                description:
                - "Requeued packets in"
                type: str
            pkts_out:
                description:
                - "Packets out"
                type: str
            total_bytes_tx:
                description:
                - "Packet bytes out"
                type: str
            unicast_pkt_tx:
                description:
                - "Unicast packets out"
                type: str
            bcast_pkt_tx:
                description:
                - "Broadcast packets out"
                type: str
            mcast_pkt_tx:
                description:
                - "Multicast packets out"
                type: str
            dropped_pkts_tx:
                description:
                - "Dropped packets out"
                type: str
            large_pkts_rx:
                description:
                - "Too large packets in"
                type: str
            dot1q_pkts_rx:
                description:
                - "Dot1q packets in"
                type: str
            frag_pkts_tx:
                description:
                - "Frag packets out"
                type: str
            reassembled_pkts_rx:
                description:
                - "Reassembled packets in"
                type: str
            bad_inner_ipv4_len_rx:
                description:
                - "bad inner ipv4 packet len"
                type: str
            bad_inner_ipv6_len_rx:
                description:
                - "Bad inner ipv6 packet len"
                type: str
            frag_drop_pkts_tx:
                description:
                - "Frag dropped packets out"
                type: str
            lif_un_init_rx:
                description:
                - "Lif uninitialized packets in"
                type: str
            id:
                description:
                - "VTEP Identifier"
                type: int

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
AVAILABLE_PROPERTIES = ["encap", "host_list", "id", "local_ip_address", "local_ipv6_address", "remote_ip_address_list", "remote_ipv6_address_list", "sampling_enable", "stats", "user_tag", "uuid", ]


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
        'id': {
            'type': 'int',
            'required': True,
            },
        'encap': {
            'type': 'str',
            'choices': ['ip-encap', 'gre', 'nvgre', 'vxlan']
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'cfg_err_count', 'flooded_pkt_count', 'encap_unresolved_count', 'unknown_encap_rx_pkt', 'unknown_encap_tx_pkt', 'arp_req_sent', 'vtep_host_learned', 'vtep_host_learn_error', 'invalid_lif_rx', 'invalid_lif_tx', 'unknown_vtep_tx', 'unknown_vtep_rx', 'unhandled_pkt_rx', 'unhandled_pkt_tx', 'total_pkts_rx', 'total_bytes_rx',
                    'unicast_pkt_rx', 'bcast_pkt_rx', 'mcast_pkt_rx', 'dropped_pkt_rx', 'encap_miss_pkts_rx', 'bad_chksum_pks_rx', 'requeue_pkts_in', 'pkts_out', 'total_bytes_tx', 'unicast_pkt_tx', 'bcast_pkt_tx', 'mcast_pkt_tx', 'dropped_pkts_tx', 'large_pkts_rx', 'dot1q_pkts_rx', 'frag_pkts_tx', 'reassembled_pkts_rx', 'bad_inner_ipv4_len_rx',
                    'bad_inner_ipv6_len_rx', 'frag_drop_pkts_tx', 'lif_un_init_rx'
                    ]
                }
            },
        'local_ip_address': {
            'type': 'dict',
            'ip_address': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'vni_list': {
                'type': 'list',
                'segment': {
                    'type': 'int',
                    'required': True,
                    },
                'partition': {
                    'type': 'str',
                    },
                'gateway': {
                    'type': 'bool',
                    },
                'lif': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'local_ipv6_address': {
            'type': 'dict',
            'ipv6_address': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'vni_list': {
                'type': 'list',
                'segment': {
                    'type': 'int',
                    'required': True,
                    },
                'partition': {
                    'type': 'str',
                    },
                'gateway': {
                    'type': 'bool',
                    },
                'lif': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'remote_ip_address_list': {
            'type': 'list',
            'ip_address': {
                'type': 'str',
                'required': True,
                },
            'class_list': {
                'type': 'str',
                },
            'encap': {
                'type': 'str',
                'choices': ['nvgre', 'vxlan']
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'use_lif': {
                'type': 'dict',
                'partition': {
                    'type': 'str',
                    },
                'lif': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'gre_keepalive': {
                'type': 'dict',
                'retry_time': {
                    'type': 'int',
                    },
                'retry_count': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'use_gre_key': {
                'type': 'dict',
                'gre_key': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'vni_list': {
                'type': 'list',
                'segment': {
                    'type': 'int',
                    'required': True,
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'remote_ipv6_address_list': {
            'type': 'list',
            'ipv6_address': {
                'type': 'str',
                'required': True,
                },
            'class_list': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'use_lif': {
                'type': 'dict',
                'partition': {
                    'type': 'str',
                    },
                'lif': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'vni_list': {
                'type': 'list',
                'segment': {
                    'type': 'int',
                    'required': True,
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'host_list': {
            'type': 'list',
            'ip_addr': {
                'type': 'str',
                'required': True,
                },
            'ipv6_addr': {
                'type': 'str',
                },
            'overlay_mac_addr': {
                'type': 'str',
                'required': True,
                },
            'vni': {
                'type': 'int',
                'required': True,
                },
            'remote_vtep': {
                'type': 'str',
                'required': True,
                },
            'remote_ipv6_vtep': {
                'type': 'str',
                'required': True,
                },
            'uuid': {
                'type': 'str',
                }
            },
        'stats': {
            'type': 'dict',
            'cfg_err_count': {
                'type': 'str',
                },
            'flooded_pkt_count': {
                'type': 'str',
                },
            'encap_unresolved_count': {
                'type': 'str',
                },
            'unknown_encap_rx_pkt': {
                'type': 'str',
                },
            'unknown_encap_tx_pkt': {
                'type': 'str',
                },
            'arp_req_sent': {
                'type': 'str',
                },
            'vtep_host_learned': {
                'type': 'str',
                },
            'vtep_host_learn_error': {
                'type': 'str',
                },
            'invalid_lif_rx': {
                'type': 'str',
                },
            'invalid_lif_tx': {
                'type': 'str',
                },
            'unknown_vtep_tx': {
                'type': 'str',
                },
            'unknown_vtep_rx': {
                'type': 'str',
                },
            'unhandled_pkt_rx': {
                'type': 'str',
                },
            'unhandled_pkt_tx': {
                'type': 'str',
                },
            'total_pkts_rx': {
                'type': 'str',
                },
            'total_bytes_rx': {
                'type': 'str',
                },
            'unicast_pkt_rx': {
                'type': 'str',
                },
            'bcast_pkt_rx': {
                'type': 'str',
                },
            'mcast_pkt_rx': {
                'type': 'str',
                },
            'dropped_pkt_rx': {
                'type': 'str',
                },
            'encap_miss_pkts_rx': {
                'type': 'str',
                },
            'bad_chksum_pks_rx': {
                'type': 'str',
                },
            'requeue_pkts_in': {
                'type': 'str',
                },
            'pkts_out': {
                'type': 'str',
                },
            'total_bytes_tx': {
                'type': 'str',
                },
            'unicast_pkt_tx': {
                'type': 'str',
                },
            'bcast_pkt_tx': {
                'type': 'str',
                },
            'mcast_pkt_tx': {
                'type': 'str',
                },
            'dropped_pkts_tx': {
                'type': 'str',
                },
            'large_pkts_rx': {
                'type': 'str',
                },
            'dot1q_pkts_rx': {
                'type': 'str',
                },
            'frag_pkts_tx': {
                'type': 'str',
                },
            'reassembled_pkts_rx': {
                'type': 'str',
                },
            'bad_inner_ipv4_len_rx': {
                'type': 'str',
                },
            'bad_inner_ipv6_len_rx': {
                'type': 'str',
                },
            'frag_drop_pkts_tx': {
                'type': 'str',
                },
            'lif_un_init_rx': {
                'type': 'str',
                },
            'id': {
                'type': 'int',
                'required': True,
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/overlay-tunnel/vtep/{id}"

    f_dict = {}
    if '/' in str(module.params["id"]):
        f_dict["id"] = module.params["id"].replace("/", "%2F")
    else:
        f_dict["id"] = module.params["id"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/overlay-tunnel/vtep"

    f_dict = {}
    f_dict["id"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["vtep"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["vtep"].get(k) != v:
            change_results["changed"] = True
            config_changes["vtep"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


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
    payload = utils.build_json("vtep", module.params, AVAILABLE_PROPERTIES)
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
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["vtep"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["vtep-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["vtep"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
