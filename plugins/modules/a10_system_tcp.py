#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_tcp
description:
    - tcp counters and global config
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
                - "'all'= all; 'activeopens'= Active open conns; 'passiveopens'= Passive open
          conns; 'attemptfails'= Connect attemp failures; 'estabresets'= Resets rcvd on
          EST conn; 'insegs'= Total in TCP packets; 'outsegs'= Total out TCP packets;
          'retranssegs'= Retransmited packets; 'inerrs'= Input errors; 'outrsts'= Reset
          Sent; 'sock_alloc'= Sockets allocated; 'orphan_count'= Orphan sockets;
          'mem_alloc'= Memory alloc; 'recv_mem'= Total rx buffer; 'send_mem'= Total tx
          buffer; 'currestab'= Currently EST conns; 'currsyssnt'= TCP in SYN-SNT state;
          'currsynrcv'= TCP in SYN-RCV state; 'currfinw1'= TCP in FIN-W1 state;
          'currfinw2'= TCP FIN-W2 state; 'currtimew'= TCP TimeW state; 'currclose'= TCP
          in Close state; 'currclsw'= TCP in CloseW state; 'currlack'= TCP in LastACK
          state; 'currlstn'= TCP in Listen state; 'currclsg'= TCP in Closing state;
          'pawsactiverejected'= TCP paw active rej; 'syn_rcv_rstack'= Rcv RST|ACK on SYN;
          'syn_rcv_rst'= Rcv RST on SYN; 'syn_rcv_ack'= Rcv ACK on SYN; 'ax_rexmit_syn'=
          TCP rexmit SYN; 'tcpabortontimeout'= TCP abort on timeout; 'noroute'= TCPIP out
          noroute; 'exceedmss'= MSS exceeded pkt dropped; 'tfo_conns'= TFO Total
          Connections; 'tfo_actives'= TFO Current Actives; 'tfo_denied'= TFO Denied;
          'syn_rcv_rexmit'= Rcv SYN rexmit; 'sock_init'= Socket init; 'invalid_drop'=
          Invalid packet drop;"
                type: str
    rate_limit_reset_unknown_conn:
        description:
        - "Field rate_limit_reset_unknown_conn"
        type: dict
        required: False
        suboptions:
            pkt_rate_for_reset_unknown_conn:
                description:
                - "Field pkt_rate_for_reset_unknown_conn"
                type: int
            log_for_reset_unknown_conn:
                description:
                - "Log when rate exceed"
                type: bool
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
            tcp_cpu_list:
                description:
                - "Field tcp_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
            rate_limit_reset_unknown_conn:
                description:
                - "Field rate_limit_reset_unknown_conn"
                type: dict
    stats:
        description:
        - "Field stats"
        type: str
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list

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
AVAILABLE_PROPERTIES = ["oper", "rate_limit_reset_unknown_conn", "sampling_enable", "stats", "uuid", ]


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
                    'all', 'activeopens', 'passiveopens', 'attemptfails', 'estabresets', 'insegs', 'outsegs', 'retranssegs', 'inerrs', 'outrsts', 'sock_alloc', 'orphan_count', 'mem_alloc', 'recv_mem', 'send_mem', 'currestab', 'currsyssnt', 'currsynrcv', 'currfinw1', 'currfinw2', 'currtimew', 'currclose', 'currclsw', 'currlack', 'currlstn',
                    'currclsg', 'pawsactiverejected', 'syn_rcv_rstack', 'syn_rcv_rst', 'syn_rcv_ack', 'ax_rexmit_syn', 'tcpabortontimeout', 'noroute', 'exceedmss', 'tfo_conns', 'tfo_actives', 'tfo_denied', 'syn_rcv_rexmit', 'sock_init', 'invalid_drop'
                    ]
                }
            },
        'rate_limit_reset_unknown_conn': {
            'type': 'dict',
            'pkt_rate_for_reset_unknown_conn': {
                'type': 'int',
                },
            'log_for_reset_unknown_conn': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'tcp_cpu_list': {
                'type': 'list',
                'currestab': {
                    'type': 'int',
                    },
                'activeopens': {
                    'type': 'int',
                    },
                'passiveopens': {
                    'type': 'int',
                    },
                'attemptfails': {
                    'type': 'int',
                    },
                'insegs': {
                    'type': 'int',
                    },
                'outsegs': {
                    'type': 'int',
                    },
                'retranssegs': {
                    'type': 'int',
                    },
                'estabresets': {
                    'type': 'int',
                    },
                'outrsts': {
                    'type': 'int',
                    },
                'noroute': {
                    'type': 'int',
                    },
                'tfo_conns': {
                    'type': 'int',
                    },
                'tfo_actives': {
                    'type': 'int',
                    },
                'tfo_denied': {
                    'type': 'int',
                    },
                'inerrs': {
                    'type': 'int',
                    },
                'sock_init': {
                    'type': 'int',
                    },
                'sock_alloc': {
                    'type': 'int',
                    },
                'orphan_count': {
                    'type': 'int',
                    },
                'mem_alloc': {
                    'type': 'int',
                    },
                'recv_mem': {
                    'type': 'int',
                    },
                'send_mem': {
                    'type': 'int',
                    },
                'currsyssnt': {
                    'type': 'int',
                    },
                'currsynrcv': {
                    'type': 'int',
                    },
                'currfinw1': {
                    'type': 'int',
                    },
                'currfinw2': {
                    'type': 'int',
                    },
                'currtimew': {
                    'type': 'int',
                    },
                'currclose': {
                    'type': 'int',
                    },
                'currclsw': {
                    'type': 'int',
                    },
                'currlack': {
                    'type': 'int',
                    },
                'currlstn': {
                    'type': 'int',
                    },
                'currclsg': {
                    'type': 'int',
                    },
                'pawsactiverejected': {
                    'type': 'int',
                    },
                'syn_rcv_rstack': {
                    'type': 'int',
                    },
                'syn_rcv_rst': {
                    'type': 'int',
                    },
                'syn_rcv_ack': {
                    'type': 'int',
                    },
                'syn_rcv_rexmit': {
                    'type': 'int',
                    },
                'tcpabortontimeout': {
                    'type': 'int',
                    },
                'ax_rexmit_syn': {
                    'type': 'int',
                    },
                'exceedmss': {
                    'type': 'int',
                    },
                'invalid_drop': {
                    'type': 'int',
                    }
                },
            'cpu_count': {
                'type': 'int',
                },
            'rate_limit_reset_unknown_conn': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'unknown_conn_rate_limit': {
                        'type': 'int',
                        },
                    'unknown_conn_current_rate': {
                        'type': 'int',
                        },
                    'unknown_conn_rate_limit_drop': {
                        'type': 'int',
                        }
                    }
                }
            },
        'stats': {
            'type': 'str',
            'required': False,
            'uuid': {
                'type': 'str',
                },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'connattempt', 'connects', 'drops', 'conndrops', 'closed', 'segstimed', 'rttupdated', 'delack', 'timeoutdrop', 'rexmttimeo', 'persisttimeo', 'keeptimeo', 'keepprobe', 'keepdrops', 'sndtotal', 'sndpack', 'sndbyte', 'sndrexmitpack', 'sndrexmitbyte', 'sndrexmitbad', 'sndacks', 'sndprobe', 'sndurg', 'sndwinup', 'sndctrl',
                        'sndrst', 'sndfin', 'sndsyn', 'rcvtotal', 'rcvpack', 'rcvbyte', 'rcvbadoff', 'rcvmemdrop', 'rcvduppack', 'rcvdupbyte', 'rcvpartduppack', 'rcvpartdupbyte', 'rcvoopack', 'rcvoobyte', 'rcvpackafterwin', 'rcvbyteafterwin', 'rcvwinprobe', 'rcvdupack', 'rcvacktoomuch', 'rcvackpack', 'rcvackbyte', 'rcvwinupd', 'pawsdrop',
                        'predack', 'preddat', 'persistdrop', 'badrst', 'finwait2_drops', 'sack_recovery_episode', 'sack_rexmits', 'sack_rexmit_bytes', 'sack_rcv_blocks', 'sack_send_blocks', 'sndcack', 'cacklim', 'reassmemdrop', 'reasstimeout', 'cc_idle', 'cc_reduce', 'rcvdsack', 'a2brcvwnd', 'a2bsackpresent', 'a2bdupack', 'a2brxdata',
                        'a2btcpoptions', 'a2boodata', 'a2bpartialack', 'a2bfsmtransition', 'a2btransitionnum', 'b2atransitionnum', 'bad_iochan', 'atcpforward', 'atcpsent', 'atcprexmitsadrop', 'atcpsendbackack', 'atcprexmit', 'atcpbuffallocfail', 'a2bappbuffering', 'atcpsendfail', 'earlyrexmit', 'mburstlim', 'a2bsndwnd', 'proxyheaderv1',
                        'proxyheaderv2'
                        ]
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/tcp"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/tcp"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["tcp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["tcp"].get(k) != v:
            change_results["changed"] = True
            config_changes["tcp"][k] = v

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
    payload = utils.build_json("tcp", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["tcp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["tcp-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["tcp"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["tcp"]["stats"] if info != "NotFound" else info
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
