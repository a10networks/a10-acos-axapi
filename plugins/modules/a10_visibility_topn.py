#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_topn
description:
    - Configure topn
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'heap-alloc-success'= Total heap node allocated; 'heap-alloc-
          failed'= Total heap node alloc failed; 'heap-alloc-oom'= Total heap node alloc
          failed Out of Memory; 'obj-reg-success'= Total object node allocated; 'obj-reg-
          failed'= Total object node alloc failed; 'obj-reg-oom'= Total object node alloc
          failed Out of Memory; 'heap-deleted'= Total Heap node deleted; 'obj-deleted'=
          Total Object node deleted; 'heap-metric-alloc-success'= Total heap metric node
          allocated; 'heap-metric-alloc-oom'= Total heap metric node alloc failed Out of
          Memory; 'heap-move-to-delq'= Total heap node moved to delq; 'heap-metric-
          deleted'= Total Heap metric node deleted; 'obj-metric-reg-success'= Total
          object Metric node allocated; 'obj-metric-reg-oom'= Total object Metric node
          alloc failed Out of Memory; 'obj-move-to-delq'= Total object node moved to
          delq; 'obj-metric-deleted'= Total Object metric node deleted; 'hc-obj-alloc-
          failed'= Send failed to HC, Out of Memory;"
                type: str
    templ_gtp_plcy_topn_tmpl_list:
        description:
        - "Field templ_gtp_plcy_topn_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Template Name"
                type: str
            topn_size:
                description:
                - "Congure value of N for topn"
                type: int
            interval:
                description:
                - "'5'= 5 minutes; '15'= 15 minutes; '30'= 30 minutes; '60'= 60 minutes; 'all-
          time'= Since template is activated;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            metrics:
                description:
                - "Field metrics"
                type: dict
    templ_gtp_plcy_topn_node:
        description:
        - "Field templ_gtp_plcy_topn_node"
        type: dict
        required: False
        suboptions:
            activate:
                description:
                - "Name of the templated to be activated"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    cgnv6_nat_pool_topn_tmpl_list:
        description:
        - "Field cgnv6_nat_pool_topn_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Template Name"
                type: str
            topn_size:
                description:
                - "Congure value of N for topn"
                type: int
            interval:
                description:
                - "'5'= 5 minutes; '15'= 15 minutes; '30'= 30 minutes; '60'= 60 minutes; 'all-
          time'= Since template is activated;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            metrics:
                description:
                - "Field metrics"
                type: dict
    cgnv6_nat_pool_topn_node:
        description:
        - "Field cgnv6_nat_pool_topn_node"
        type: dict
        required: False
        suboptions:
            activate:
                description:
                - "Name of the templated to be activated"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    gtp_apn_prefix_topn_tmpl_list:
        description:
        - "Field gtp_apn_prefix_topn_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Template Name"
                type: str
            topn_size:
                description:
                - "Congure value of N for topn"
                type: int
            interval:
                description:
                - "'5'= 5 minutes; '15'= 15 minutes; '30'= 30 minutes; '60'= 60 minutes; 'all-
          time'= Since template is activated;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            metrics:
                description:
                - "Field metrics"
                type: dict
    gtp_apn_prefix_topn_node:
        description:
        - "Field gtp_apn_prefix_topn_node"
        type: dict
        required: False
        suboptions:
            activate:
                description:
                - "Name of the templated to be activated"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    gtp_network_element_topn_tmpl_list:
        description:
        - "Field gtp_network_element_topn_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Template Name"
                type: str
            topn_size:
                description:
                - "Congure value of N for topn"
                type: int
            interval:
                description:
                - "'5'= 5 minutes; '15'= 15 minutes; '30'= 30 minutes; '60'= 60 minutes; 'all-
          time'= Since template is activated;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            metrics:
                description:
                - "Field metrics"
                type: dict
    gtp_network_element_topn_node:
        description:
        - "Field gtp_network_element_topn_node"
        type: dict
        required: False
        suboptions:
            activate:
                description:
                - "Name of the templated to be activated"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            class:
                description:
                - "Field class"
                type: str
            metric:
                description:
                - "Field metric"
                type: str
            memory_usage:
                description:
                - "Field memory_usage"
                type: bool
            topn_duration:
                description:
                - "Field topn_duration"
                type: str
            metric_topn_list:
                description:
                - "Field metric_topn_list"
                type: list
            total_memory:
                description:
                - "Field total_memory"
                type: str
            used_memory:
                description:
                - "Field used_memory"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            heap_alloc_success:
                description:
                - "Total heap node allocated"
                type: str
            heap_alloc_failed:
                description:
                - "Total heap node alloc failed"
                type: str
            heap_alloc_oom:
                description:
                - "Total heap node alloc failed Out of Memory"
                type: str
            obj_reg_success:
                description:
                - "Total object node allocated"
                type: str
            obj_reg_failed:
                description:
                - "Total object node alloc failed"
                type: str
            obj_reg_oom:
                description:
                - "Total object node alloc failed Out of Memory"
                type: str
            heap_deleted:
                description:
                - "Total Heap node deleted"
                type: str
            obj_deleted:
                description:
                - "Total Object node deleted"
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
AVAILABLE_PROPERTIES = ["cgnv6_nat_pool_topn_node", "cgnv6_nat_pool_topn_tmpl_list", "gtp_apn_prefix_topn_node", "gtp_apn_prefix_topn_tmpl_list", "gtp_network_element_topn_node", "gtp_network_element_topn_tmpl_list", "oper", "sampling_enable", "stats", "templ_gtp_plcy_topn_node", "templ_gtp_plcy_topn_tmpl_list", "uuid", ]


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
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'heap-alloc-success', 'heap-alloc-failed', 'heap-alloc-oom', 'obj-reg-success', 'obj-reg-failed', 'obj-reg-oom', 'heap-deleted', 'obj-deleted', 'heap-metric-alloc-success', 'heap-metric-alloc-oom', 'heap-move-to-delq', 'heap-metric-deleted', 'obj-metric-reg-success', 'obj-metric-reg-oom', 'obj-move-to-delq',
                    'obj-metric-deleted', 'hc-obj-alloc-failed'
                    ]
                }
            },
        'templ_gtp_plcy_topn_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'topn_size': {
                'type': 'int',
                },
            'interval': {
                'type': 'str',
                'choices': ['5', '15', '30', '60', 'all-time']
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'metrics': {
                'type': 'dict',
                'rl_message_monitor': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'templ_gtp_plcy_topn_node': {
            'type': 'dict',
            'activate': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'cgnv6_nat_pool_topn_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'topn_size': {
                'type': 'int',
                },
            'interval': {
                'type': 'str',
                'choices': ['5', '15', '30', '60', 'all-time']
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'metrics': {
                'type': 'dict',
                'udp_total': {
                    'type': 'bool',
                    },
                'tcp_total': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'cgnv6_nat_pool_topn_node': {
            'type': 'dict',
            'activate': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'gtp_apn_prefix_topn_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'topn_size': {
                'type': 'int',
                },
            'interval': {
                'type': 'str',
                'choices': ['5', '15', '30', '60', 'all-time']
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'metrics': {
                'type': 'dict',
                'uplink_bytes': {
                    'type': 'bool',
                    },
                'downlink_bytes': {
                    'type': 'bool',
                    },
                'uplink_pkts': {
                    'type': 'bool',
                    },
                'downlink_pkts': {
                    'type': 'bool',
                    },
                'u_uplink_bytes': {
                    'type': 'bool',
                    },
                'u_downlink_bytes': {
                    'type': 'bool',
                    },
                'u_uplink_pkts': {
                    'type': 'bool',
                    },
                'u_downlink_pkts': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_created': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_half_open': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_half_closed': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_deleted': {
                    'type': 'bool',
                    },
                'gtp_v0_c_half_open_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_created': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_half_open': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_half_closed': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_deleted': {
                    'type': 'bool',
                    },
                'gtp_v1_c_half_open_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_created': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_half_open': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_half_closed': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_deleted': {
                    'type': 'bool',
                    },
                'gtp_v2_c_half_open_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_u_tunnel_created': {
                    'type': 'bool',
                    },
                'gtp_u_tunnel_deleted': {
                    'type': 'bool',
                    },
                'gtp_v0_c_update_pdp_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v1_c_update_pdp_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v2_c_mod_bearer_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v0_c_create_pdp_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v1_c_create_pdp_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v2_c_create_sess_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v2_c_piggyback_message': {
                    'type': 'bool',
                    },
                'gtp_path_management_message': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_deleted_restart': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_deleted_restart': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_deleted_restart': {
                    'type': 'bool',
                    },
                'drop_vld_reserved_field_set': {
                    'type': 'bool',
                    },
                'drop_vld_tunnel_id_flag': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_flow_label_v0': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_teid': {
                    'type': 'bool',
                    },
                'drop_vld_unsupported_message_type': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_state': {
                    'type': 'bool',
                    },
                'drop_vld_mandatory_information_element': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_order_ie': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_state_ie': {
                    'type': 'bool',
                    },
                'drop_vld_reserved_information_element': {
                    'type': 'bool',
                    },
                'drop_vld_version_not_supported': {
                    'type': 'bool',
                    },
                'drop_vld_message_length': {
                    'type': 'bool',
                    },
                'drop_vld_cross_layer_correlation': {
                    'type': 'bool',
                    },
                'drop_vld_country_code_mismatch': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_u_spoofed_source_address': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_bearer_count_exceed': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_v2_wrong_lbi_create_bearer': {
                    'type': 'bool',
                    },
                'gtp_c_handover_in_progress_with_conn': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_pkt_len_piggyback': {
                    'type': 'bool',
                    },
                'drop_vld_sanity_failed_piggyback': {
                    'type': 'bool',
                    },
                'drop_vld_sequence_num_correlation': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv0_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv1_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv2_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_invalid_imsi_len_drop': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_invalid_apn_len_drop': {
                    'type': 'bool',
                    },
                'drop_vld_protocol_flag_unset': {
                    'type': 'bool',
                    },
                'drop_flt_message_filtering': {
                    'type': 'bool',
                    },
                'drop_flt_apn_filtering': {
                    'type': 'bool',
                    },
                'drop_flt_msisdn_filtering': {
                    'type': 'bool',
                    },
                'drop_flt_rat_type_filtering': {
                    'type': 'bool',
                    },
                'drop_flt_gtp_in_gtp': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v0_c_agg': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v1_c_agg': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v2_c_agg': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v1_c_create_pdp_request': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v2_c_create_session_request': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v1_c_update_pdp_request': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v2_c_modify_bearer_request': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_tunnel_create': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_uplink_byte': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_uplink_packet': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_downlink_byte': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_downlink_packet': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_total_byte': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_total_packet': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_max_concurrent_tunnels': {
                    'type': 'bool',
                    },
                'rl_message_monitor': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'gtp_apn_prefix_topn_node': {
            'type': 'dict',
            'activate': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'gtp_network_element_topn_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'topn_size': {
                'type': 'int',
                },
            'interval': {
                'type': 'str',
                'choices': ['5', '15', '30', '60', 'all-time']
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'metrics': {
                'type': 'dict',
                'uplink_bytes': {
                    'type': 'bool',
                    },
                'downlink_bytes': {
                    'type': 'bool',
                    },
                'uplink_pkts': {
                    'type': 'bool',
                    },
                'downlink_pkts': {
                    'type': 'bool',
                    },
                'u_uplink_bytes': {
                    'type': 'bool',
                    },
                'u_downlink_bytes': {
                    'type': 'bool',
                    },
                'u_uplink_pkts': {
                    'type': 'bool',
                    },
                'u_downlink_pkts': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_created': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_half_open': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_half_closed': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_deleted': {
                    'type': 'bool',
                    },
                'gtp_v0_c_half_open_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_created': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_half_open': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_half_closed': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_deleted': {
                    'type': 'bool',
                    },
                'gtp_v1_c_half_open_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_created': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_half_open': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_half_closed': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_deleted': {
                    'type': 'bool',
                    },
                'gtp_v2_c_half_open_tunnel_closed': {
                    'type': 'bool',
                    },
                'gtp_u_tunnel_created': {
                    'type': 'bool',
                    },
                'gtp_u_tunnel_deleted': {
                    'type': 'bool',
                    },
                'gtp_v0_c_update_pdp_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v1_c_update_pdp_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v2_c_mod_bearer_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v0_c_create_pdp_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v1_c_create_pdp_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v2_c_create_sess_resp_unsuccess': {
                    'type': 'bool',
                    },
                'gtp_v2_c_piggyback_message': {
                    'type': 'bool',
                    },
                'gtp_path_management_message': {
                    'type': 'bool',
                    },
                'gtp_v0_c_tunnel_deleted_restart': {
                    'type': 'bool',
                    },
                'gtp_v1_c_tunnel_deleted_restart': {
                    'type': 'bool',
                    },
                'gtp_v2_c_tunnel_deleted_restart': {
                    'type': 'bool',
                    },
                'gtp_v0_c_reserved_message_allow': {
                    'type': 'bool',
                    },
                'gtp_v1_c_reserved_message_allow': {
                    'type': 'bool',
                    },
                'gtp_v2_c_reserved_message_allow': {
                    'type': 'bool',
                    },
                'drop_vld_reserved_field_set': {
                    'type': 'bool',
                    },
                'drop_vld_tunnel_id_flag': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_flow_label_v0': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_teid': {
                    'type': 'bool',
                    },
                'drop_vld_unsupported_message_type': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_state': {
                    'type': 'bool',
                    },
                'drop_vld_mandatory_information_element': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_order_ie': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_state_ie': {
                    'type': 'bool',
                    },
                'drop_vld_reserved_information_element': {
                    'type': 'bool',
                    },
                'drop_vld_version_not_supported': {
                    'type': 'bool',
                    },
                'drop_vld_message_length': {
                    'type': 'bool',
                    },
                'drop_vld_cross_layer_correlation': {
                    'type': 'bool',
                    },
                'drop_vld_country_code_mismatch': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_u_spoofed_source_address': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_bearer_count_exceed': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_v2_wrong_lbi_create_bearer': {
                    'type': 'bool',
                    },
                'gtp_c_handover_in_progress_with_conn': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_pkt_len_piggyback': {
                    'type': 'bool',
                    },
                'drop_vld_sanity_failed_piggyback': {
                    'type': 'bool',
                    },
                'drop_vld_sequence_num_correlation': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv0_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv1_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv2_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_invalid_imsi_len_drop': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_invalid_apn_len_drop': {
                    'type': 'bool',
                    },
                'drop_vld_protocol_flag_unset': {
                    'type': 'bool',
                    },
                'drop_flt_message_filtering': {
                    'type': 'bool',
                    },
                'drop_flt_apn_filtering': {
                    'type': 'bool',
                    },
                'drop_flt_msisdn_filtering': {
                    'type': 'bool',
                    },
                'drop_flt_rat_type_filtering': {
                    'type': 'bool',
                    },
                'drop_flt_gtp_in_gtp': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v0_c_agg': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v1_c_agg': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v2_c_agg': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v1_c_create_pdp_request': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v2_c_create_session_request': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v1_c_update_pdp_request': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_v2_c_modify_bearer_request': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_tunnel_create': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_uplink_byte': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_uplink_packet': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_downlink_byte': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_downlink_packet': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_total_byte': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_total_packet': {
                    'type': 'bool',
                    },
                'drop_rl_gtp_u_max_concurrent_tunnels': {
                    'type': 'bool',
                    },
                'rl_message_monitor': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'gtp_network_element_topn_node': {
            'type': 'dict',
            'activate': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'class': {
                'type': 'str',
                },
            'metric': {
                'type': 'str',
                },
            'memory_usage': {
                'type': 'bool',
                },
            'topn_duration': {
                'type': 'str',
                },
            'metric_topn_list': {
                'type': 'list',
                'object_name': {
                    'type': 'str',
                    },
                'object_val': {
                    'type': 'int',
                    }
                },
            'total_memory': {
                'type': 'str',
                },
            'used_memory': {
                'type': 'str',
                }
            },
        'stats': {
            'type': 'dict',
            'heap_alloc_success': {
                'type': 'str',
                },
            'heap_alloc_failed': {
                'type': 'str',
                },
            'heap_alloc_oom': {
                'type': 'str',
                },
            'obj_reg_success': {
                'type': 'str',
                },
            'obj_reg_failed': {
                'type': 'str',
                },
            'obj_reg_oom': {
                'type': 'str',
                },
            'heap_deleted': {
                'type': 'str',
                },
            'obj_deleted': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/topn"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/topn"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["topn"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["topn"].get(k) != v:
            change_results["changed"] = True
            config_changes["topn"][k] = v

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
    payload = utils.build_json("topn", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["topn"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["topn-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["topn"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["topn"]["stats"] if info != "NotFound" else info
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
