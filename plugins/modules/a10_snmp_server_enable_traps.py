#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_snmp_server_enable_traps
description:
    - Enable SNMP traps
short_description: Configures A10 snmp.server.enable.traps
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
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
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
    lldp:
        description:
        - "Enable lldp traps"
        required: False
    all:
        description:
        - "Enable all SNMP traps"
        required: False
    slb_change:
        description:
        - "Field slb_change"
        required: False
        suboptions:
            all:
                description:
                - "Enable all system group traps"
            resource_usage_warning:
                description:
                - "Enable partition resource usage warning trap"
            uuid:
                description:
                - "uuid of the object"
            ssl_cert_change:
                description:
                - "Enable SSL certificate change trap"
            ssl_cert_expire:
                description:
                - "Enable SSL certificate expiring trap"
            system_threshold:
                description:
                - "Enable slb system threshold trap"
            server:
                description:
                - "Enable slb server create/delete trap"
            vip:
                description:
                - "Enable slb vip create/delete trap"
            connection_resource_event:
                description:
                - "Enable system connection resource event trap"
            server_port:
                description:
                - "Enable slb server port create/delete trap"
            vip_port:
                description:
                - "Enable slb vip-port create/delete trap"
    uuid:
        description:
        - "uuid of the object"
        required: False
    lsn:
        description:
        - "Field lsn"
        required: False
        suboptions:
            all:
                description:
                - "Enable all LSN group traps"
            fixed_nat_port_mapping_file_change:
                description:
                - "Enable LSN trap when fixed nat port mapping file change"
            per_ip_port_usage_threshold:
                description:
                - "Enable LSN trap when IP total port usage reaches the threshold (default 64512)"
            uuid:
                description:
                - "uuid of the object"
            total_port_usage_threshold:
                description:
                - "Enable LSN trap when NAT total port usage reaches the threshold (default
          655350000)"
            max_port_threshold:
                description:
                - "Maximum threshold"
            max_ipport_threshold:
                description:
                - "Maximum threshold"
            traffic_exceeded:
                description:
                - "Enable LSN trap when NAT pool reaches the threshold"
    vrrp_a:
        description:
        - "Field vrrp_a"
        required: False
        suboptions:
            active:
                description:
                - "Enable VRRP-A active trap"
            standby:
                description:
                - "Enable VRRP-A standby trap"
            all:
                description:
                - "Enable all VRRP-A group traps"
            uuid:
                description:
                - "uuid of the object"
    snmp:
        description:
        - "Field snmp"
        required: False
        suboptions:
            linkup:
                description:
                - "Enable SNMP link-up trap"
            all:
                description:
                - "Enable all SNMP group traps"
            linkdown:
                description:
                - "Enable SNMP link-down trap"
            uuid:
                description:
                - "uuid of the object"
    system:
        description:
        - "Field system"
        required: False
        suboptions:
            all:
                description:
                - "Enable all system group traps"
            data_cpu_high:
                description:
                - "Enable data CPU usage high trap"
            uuid:
                description:
                - "uuid of the object"
            power:
                description:
                - "Enable system power supply trap"
            high_disk_use:
                description:
                - "Enable system high disk usage trap"
            high_memory_use:
                description:
                - "Enable system high memory usage trap"
            control_cpu_high:
                description:
                - "Enable control CPU usage high trap"
            file_sys_read_only:
                description:
                - "Enable file system read-only trap"
            low_temp:
                description:
                - "Enable system low temperature trap"
            high_temp:
                description:
                - "Enable system high temperature trap"
            sec_disk:
                description:
                - "Enable system secondary hard disk trap"
            license_management:
                description:
                - "Enable system license management traps"
            start:
                description:
                - "Enable system start trap"
            fan:
                description:
                - "Enable system fan trap"
            shutdown:
                description:
                - "Enable system shutdown trap"
            pri_disk:
                description:
                - "Enable system primary hard disk trap"
            syslog_severity_one:
                description:
                - "Enable system syslog severity one messages trap"
            tacacs_server_up_down:
                description:
                - "Enable system TACACS monitor server up/down trap"
            smp_resource_event:
                description:
                - "Enable system smp resource event trap"
            restart:
                description:
                - "Enable system restart trap"
            packet_drop:
                description:
                - "Enable system packet dropped trap"
    ssl:
        description:
        - "Field ssl"
        required: False
        suboptions:
            server_certificate_error:
                description:
                - "Enable SSL server certificate error trap"
            uuid:
                description:
                - "uuid of the object"
    vcs:
        description:
        - "Field vcs"
        required: False
        suboptions:
            state_change:
                description:
                - "Enable VCS state change trap"
            uuid:
                description:
                - "uuid of the object"
    routing:
        description:
        - "Field routing"
        required: False
        suboptions:
            bgp:
                description:
                - "Field bgp"
            isis:
                description:
                - "Field isis"
            ospf:
                description:
                - "Field ospf"
    gslb:
        description:
        - "Field gslb"
        required: False
        suboptions:
            all:
                description:
                - "Enable all GSLB traps"
            group:
                description:
                - "Enable GSLB group related traps"
            uuid:
                description:
                - "uuid of the object"
            zone:
                description:
                - "Enable GSLB zone related traps"
            site:
                description:
                - "Enable GSLB site related traps"
            service_ip:
                description:
                - "Enable GSLB service-ip related traps"
    slb:
        description:
        - "Field slb"
        required: False
        suboptions:
            all:
                description:
                - "Enable all SLB traps"
            server_down:
                description:
                - "Enable SLB server-down trap"
            vip_port_connratelimit:
                description:
                - "Enable the virtual port reach conn-rate-limit trap"
            server_selection_failure:
                description:
                - "Enable SLB server selection failure trap"
            service_group_down:
                description:
                - "Enable SLB service-group-down trap"
            server_conn_limit:
                description:
                - "Enable SLB server connection limit trap"
            service_group_member_up:
                description:
                - "Enable SLB service-group-member-up trap"
            uuid:
                description:
                - "uuid of the object"
            server_conn_resume:
                description:
                - "Enable SLB server connection resume trap"
            service_up:
                description:
                - "Enable SLB service-up trap"
            service_conn_limit:
                description:
                - "Enable SLB service connection limit trap"
            gateway_up:
                description:
                - "Enable SLB server gateway up trap"
            service_group_up:
                description:
                - "Enable SLB service-group-up trap"
            application_buffer_limit:
                description:
                - "Enable application buffer reach limit trap"
            vip_connratelimit:
                description:
                - "Enable the virtual server reach conn-rate-limit trap"
            vip_connlimit:
                description:
                - "Enable the virtual server reach conn-limit trap"
            service_group_member_down:
                description:
                - "Enable SLB service-group-member-down trap"
            service_down:
                description:
                - "Enable SLB service-down trap"
            bw_rate_limit_exceed:
                description:
                - "Enable SLB server/port bandwidth rate limit exceed trap"
            server_disabled:
                description:
                - "Enable SLB server-disabled trap"
            server_up:
                description:
                - "Enable slb server up trap"
            vip_port_connlimit:
                description:
                - "Enable the virtual port reach conn-limit trap"
            vip_port_down:
                description:
                - "Enable SLB virtual port down trap"
            bw_rate_limit_resume:
                description:
                - "Enable SLB server/port bandwidth rate limit resume trap"
            gateway_down:
                description:
                - "Enable SLB server gateway down trap"
            vip_up:
                description:
                - "Enable SLB virtual server up trap"
            vip_port_up:
                description:
                - "Enable SLB virtual port up trap"
            vip_down:
                description:
                - "Enable SLB virtual server down trap"
            service_conn_resume:
                description:
                - "Enable SLB service connection resume trap"
    network:
        description:
        - "Field network"
        required: False
        suboptions:
            trunk_port_threshold:
                description:
                - "Enable network trunk-port-threshold trap"
            uuid:
                description:
                - "uuid of the object"


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
    "all",
    "gslb",
    "lldp",
    "lsn",
    "network",
    "routing",
    "slb",
    "slb_change",
    "snmp",
    "ssl",
    "system",
    "uuid",
    "vcs",
    "vrrp_a",
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
        'lldp': {
            'type': 'bool',
        },
        'all': {
            'type': 'bool',
        },
        'slb_change': {
            'type': 'dict',
            'all': {
                'type': 'bool',
            },
            'resource_usage_warning': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'ssl_cert_change': {
                'type': 'bool',
            },
            'ssl_cert_expire': {
                'type': 'bool',
            },
            'system_threshold': {
                'type': 'bool',
            },
            'server': {
                'type': 'bool',
            },
            'vip': {
                'type': 'bool',
            },
            'connection_resource_event': {
                'type': 'bool',
            },
            'server_port': {
                'type': 'bool',
            },
            'vip_port': {
                'type': 'bool',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'lsn': {
            'type': 'dict',
            'all': {
                'type': 'bool',
            },
            'fixed_nat_port_mapping_file_change': {
                'type': 'bool',
            },
            'per_ip_port_usage_threshold': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'total_port_usage_threshold': {
                'type': 'bool',
            },
            'max_port_threshold': {
                'type': 'int',
            },
            'max_ipport_threshold': {
                'type': 'int',
            },
            'traffic_exceeded': {
                'type': 'bool',
            }
        },
        'vrrp_a': {
            'type': 'dict',
            'active': {
                'type': 'bool',
            },
            'standby': {
                'type': 'bool',
            },
            'all': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'snmp': {
            'type': 'dict',
            'linkup': {
                'type': 'bool',
            },
            'all': {
                'type': 'bool',
            },
            'linkdown': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'system': {
            'type': 'dict',
            'all': {
                'type': 'bool',
            },
            'data_cpu_high': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'power': {
                'type': 'bool',
            },
            'high_disk_use': {
                'type': 'bool',
            },
            'high_memory_use': {
                'type': 'bool',
            },
            'control_cpu_high': {
                'type': 'bool',
            },
            'file_sys_read_only': {
                'type': 'bool',
            },
            'low_temp': {
                'type': 'bool',
            },
            'high_temp': {
                'type': 'bool',
            },
            'sec_disk': {
                'type': 'bool',
            },
            'license_management': {
                'type': 'bool',
            },
            'start': {
                'type': 'bool',
            },
            'fan': {
                'type': 'bool',
            },
            'shutdown': {
                'type': 'bool',
            },
            'pri_disk': {
                'type': 'bool',
            },
            'syslog_severity_one': {
                'type': 'bool',
            },
            'tacacs_server_up_down': {
                'type': 'bool',
            },
            'smp_resource_event': {
                'type': 'bool',
            },
            'restart': {
                'type': 'bool',
            },
            'packet_drop': {
                'type': 'bool',
            }
        },
        'ssl': {
            'type': 'dict',
            'server_certificate_error': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'vcs': {
            'type': 'dict',
            'state_change': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'routing': {
            'type': 'dict',
            'bgp': {
                'type': 'dict',
                'bgpEstablishedNotification': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'bgpBackwardTransNotification': {
                    'type': 'bool',
                }
            },
            'isis': {
                'type': 'dict',
                'isisAuthenticationFailure': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'isisProtocolsSupportedMismatch': {
                    'type': 'bool',
                },
                'isisRejectedAdjacency': {
                    'type': 'bool',
                },
                'isisMaxAreaAddressesMismatch': {
                    'type': 'bool',
                },
                'isisCorruptedLSPDetected': {
                    'type': 'bool',
                },
                'isisOriginatingLSPBufferSizeMismatch': {
                    'type': 'bool',
                },
                'isisAreaMismatch': {
                    'type': 'bool',
                },
                'isisLSPTooLargeToPropagate': {
                    'type': 'bool',
                },
                'isisOwnLSPPurge': {
                    'type': 'bool',
                },
                'isisSequenceNumberSkip': {
                    'type': 'bool',
                },
                'isisDatabaseOverload': {
                    'type': 'bool',
                },
                'isisAttemptToExceedMaxSequence': {
                    'type': 'bool',
                },
                'isisIDLenMismatch': {
                    'type': 'bool',
                },
                'isisAuthenticationTypeFailure': {
                    'type': 'bool',
                },
                'isisVersionSkew': {
                    'type': 'bool',
                },
                'isisManualAddressDrops': {
                    'type': 'bool',
                },
                'isisAdjacencyChange': {
                    'type': 'bool',
                }
            },
            'ospf': {
                'type': 'dict',
                'ospfLsdbOverflow': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'ospfNbrStateChange': {
                    'type': 'bool',
                },
                'ospfIfStateChange': {
                    'type': 'bool',
                },
                'ospfVirtNbrStateChange': {
                    'type': 'bool',
                },
                'ospfLsdbApproachingOverflow': {
                    'type': 'bool',
                },
                'ospfIfAuthFailure': {
                    'type': 'bool',
                },
                'ospfVirtIfAuthFailure': {
                    'type': 'bool',
                },
                'ospfVirtIfConfigError': {
                    'type': 'bool',
                },
                'ospfVirtIfRxBadPacket': {
                    'type': 'bool',
                },
                'ospfTxRetransmit': {
                    'type': 'bool',
                },
                'ospfVirtIfStateChange': {
                    'type': 'bool',
                },
                'ospfIfConfigError': {
                    'type': 'bool',
                },
                'ospfMaxAgeLsa': {
                    'type': 'bool',
                },
                'ospfIfRxBadPacket': {
                    'type': 'bool',
                },
                'ospfVirtIfTxRetransmit': {
                    'type': 'bool',
                },
                'ospfOriginateLsa': {
                    'type': 'bool',
                }
            }
        },
        'gslb': {
            'type': 'dict',
            'all': {
                'type': 'bool',
            },
            'group': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'zone': {
                'type': 'bool',
            },
            'site': {
                'type': 'bool',
            },
            'service_ip': {
                'type': 'bool',
            }
        },
        'slb': {
            'type': 'dict',
            'all': {
                'type': 'bool',
            },
            'server_down': {
                'type': 'bool',
            },
            'vip_port_connratelimit': {
                'type': 'bool',
            },
            'server_selection_failure': {
                'type': 'bool',
            },
            'service_group_down': {
                'type': 'bool',
            },
            'server_conn_limit': {
                'type': 'bool',
            },
            'service_group_member_up': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'server_conn_resume': {
                'type': 'bool',
            },
            'service_up': {
                'type': 'bool',
            },
            'service_conn_limit': {
                'type': 'bool',
            },
            'gateway_up': {
                'type': 'bool',
            },
            'service_group_up': {
                'type': 'bool',
            },
            'application_buffer_limit': {
                'type': 'bool',
            },
            'vip_connratelimit': {
                'type': 'bool',
            },
            'vip_connlimit': {
                'type': 'bool',
            },
            'service_group_member_down': {
                'type': 'bool',
            },
            'service_down': {
                'type': 'bool',
            },
            'bw_rate_limit_exceed': {
                'type': 'bool',
            },
            'server_disabled': {
                'type': 'bool',
            },
            'server_up': {
                'type': 'bool',
            },
            'vip_port_connlimit': {
                'type': 'bool',
            },
            'vip_port_down': {
                'type': 'bool',
            },
            'bw_rate_limit_resume': {
                'type': 'bool',
            },
            'gateway_down': {
                'type': 'bool',
            },
            'vip_up': {
                'type': 'bool',
            },
            'vip_port_up': {
                'type': 'bool',
            },
            'vip_down': {
                'type': 'bool',
            },
            'service_conn_resume': {
                'type': 'bool',
            }
        },
        'network': {
            'type': 'dict',
            'trunk_port_threshold': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/snmp-server/enable/traps"

    f_dict = {}

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


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
    url_base = "/axapi/v3/snmp-server/enable/traps"

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
        for k, v in payload["traps"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["traps"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["traps"][k] = v
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
    payload = build_json("traps", module)
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
