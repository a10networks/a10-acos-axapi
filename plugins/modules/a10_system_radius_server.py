#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_radius_server
description:
    - Configure system as a RADIUS server
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
    listen_port:
        description:
        - "Configure the listen port of RADIUS server (default 1813) (Port number)"
        type: int
        required: False
    remote:
        description:
        - "Field remote"
        type: dict
        required: False
        suboptions:
            ip_list:
                description:
                - "Field ip_list"
                type: list
    secret:
        description:
        - "Configure shared secret"
        type: bool
        required: False
    secret_string:
        description:
        - "The RADIUS secret"
        type: str
        required: False
    encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
        type: str
        required: False
    vrid:
        description:
        - "Join a VRRP-A failover group"
        type: int
        required: False
    attribute:
        description:
        - "Field attribute"
        type: list
        required: False
        suboptions:
            attribute_value:
                description:
                - "'inside-ipv6-prefix'= Framed IPv6 Prefix; 'inside-ip'= Inside IP address;
          'inside-ipv6'= Inside IPv6 address; 'imei'= International Mobile Equipment
          Identity (IMEI); 'imsi'= International Mobile Subscriber Identity (IMSI);
          'msisdn'= Mobile Subscriber Integrated Services Digital Network-Number
          (MSISDN); 'custom1'= Customized attribute 1; 'custom2'= Customized attribute 2;
          'custom3'= Customized attribute 3;"
                type: str
            prefix_length:
                description:
                - "'32'= Prefix length 32; '48'= Prefix length 48; '64'= Prefix length 64; '80'=
          Prefix length 80; '96'= Prefix length 96; '112'= Prefix length 112;"
                type: str
            prefix_vendor:
                description:
                - "RADIUS vendor attribute information (RADIUS vendor ID)"
                type: int
            prefix_number:
                description:
                - "RADIUS attribute number"
                type: int
            name:
                description:
                - "Customized attribute name"
                type: str
            value:
                description:
                - "'hexadecimal'= Type of attribute value is hexadecimal;"
                type: str
            custom_vendor:
                description:
                - "RADIUS vendor attribute information (RADIUS vendor ID)"
                type: int
            custom_number:
                description:
                - "RADIUS attribute number"
                type: int
            vendor:
                description:
                - "RADIUS vendor attribute information (RADIUS vendor ID)"
                type: int
            number:
                description:
                - "RADIUS attribute number"
                type: int
    disable_reply:
        description:
        - "Toggle option for RADIUS reply packet(Default= Accounting response will be
          sent)"
        type: bool
        required: False
    accounting_start:
        description:
        - "'ignore'= Ignore; 'append-entry'= Append the AVPs to existing entry (default);
          'replace-entry'= Replace the AVPs of existing entry;"
        type: str
        required: False
    accounting_stop:
        description:
        - "'ignore'= Ignore; 'delete-entry'= Delete the entry (default); 'delete-entry-
          and-sessions'= Delete the entry and data sessions associated(CGN only);"
        type: str
        required: False
    accounting_interim_update:
        description:
        - "'ignore'= Ignore (default); 'append-entry'= Append the AVPs to existing entry;
          'replace-entry'= Replace the AVPs of existing entry;"
        type: str
        required: False
    accounting_on:
        description:
        - "'ignore'= Ignore (default); 'delete-entries-using-attribute'= Delete entries
          matching attribute in RADIUS Table;"
        type: str
        required: False
    attribute_name:
        description:
        - "'msisdn'= Clear using MSISDN; 'imei'= Clear using IMEI; 'imsi'= Clear using
          IMSI; 'custom1'= Clear using CUSTOM1 attribute configured; 'custom2'= Clear
          using CUSTOM2 attribute configured; 'custom3'= Clear using CUSTOM3 attribute
          configured;"
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
                - "'all'= all; 'msisdn-received'= MSISDN Received; 'imei-received'= IMEI Received;
          'imsi-received'= IMSI Received; 'custom-received'= Custom attribute Received;
          'radius-request-received'= RADIUS Request Received; 'radius-request-dropped'=
          RADIUS Request Dropped (Malformed Packet); 'request-bad-secret-dropped'= RADIUS
          Request Bad Secret Dropped; 'request-no-key-vap-dropped'= RADIUS Request No Key
          Attribute Dropped; 'request-malformed-dropped'= RADIUS Request Malformed
          Dropped; 'request-ignored'= RADIUS Request Ignored; 'radius-table-full'= RADIUS
          Request Dropped (Table Full); 'secret-not-configured-dropped'= RADIUS Secret
          Not Configured Dropped; 'ha-standby-dropped'= HA Standby Dropped; 'ipv6-prefix-
          length-mismatch'= Framed IPV6 Prefix Length Mismatch; 'invalid-key'= Radius
          Request has Invalid Key Field; 'smp-created'= RADIUS SMP Created; 'smp-
          deleted'= RADIUS SMP Deleted; 'smp-mem-allocated'= RADIUS SMP Memory Allocated;
          'smp-mem-alloc-failed'= RADIUS SMP Memory Allocation Failed; 'smp-mem-freed'=
          RADIUS SMP Memory Freed; 'smp-in-rml'= RADIUS SMP in RML; 'mem-allocated'=
          RADIUS Memory Allocated; 'mem-alloc-failed'= RADIUS Memory Allocation Failed;
          'mem-freed'= RADIUS Memory Freed; 'ha-sync-create-sent'= HA Record Sync Create
          Sent; 'ha-sync-delete-sent'= HA Record Sync Delete Sent; 'ha-sync-create-recv'=
          HA Record Sync Create Received; 'ha-sync-delete-recv'= HA Record Sync Delete
          Received; 'acct-on-filters-full'= RADIUS Acct On Request Ignored(Filters Full);
          'acct-on-dup-request'= Duplicate RADIUS Acct On Request; 'ip-mismatch-delete'=
          Radius Entry IP Mismatch Delete; 'ip-add-race-drop'= Radius Entry IP Add Race
          Drop; 'ha-sync-no-key-vap-dropped'= HA Record Sync No key dropped; 'inter-card-
          msg-fail-drop'= Inter-Card Message Fail Drop; 'radius-packets-redirected'=
          RADIUS packets redirected (SO); 'radius-packets-redirect-fail-dropped'= RADIUS
          packets dropped due to redirect failure (SO); 'radius-packets-process-local'=
          RADIUS packets processed locally without redirection (SO); 'radius-packets-
          dropped-not-lo'= RADIUS packets dropped dest not loopback (SO);"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            radius_table_entries_list:
                description:
                - "Field radius_table_entries_list"
                type: list
            total_entries:
                description:
                - "Field total_entries"
                type: int
            custom_attr_name:
                description:
                - "Field custom_attr_name"
                type: str
            custom_attr_value:
                description:
                - "Field custom_attr_value"
                type: str
            starts_with:
                description:
                - "Field starts_with"
                type: bool
            case_insensitive:
                description:
                - "Field case_insensitive"
                type: bool
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            msisdn_received:
                description:
                - "MSISDN Received"
                type: str
            imei_received:
                description:
                - "IMEI Received"
                type: str
            imsi_received:
                description:
                - "IMSI Received"
                type: str
            custom_received:
                description:
                - "Custom attribute Received"
                type: str
            radius_request_received:
                description:
                - "RADIUS Request Received"
                type: str
            radius_request_dropped:
                description:
                - "RADIUS Request Dropped (Malformed Packet)"
                type: str
            request_bad_secret_dropped:
                description:
                - "RADIUS Request Bad Secret Dropped"
                type: str
            request_no_key_vap_dropped:
                description:
                - "RADIUS Request No Key Attribute Dropped"
                type: str
            request_malformed_dropped:
                description:
                - "RADIUS Request Malformed Dropped"
                type: str
            request_ignored:
                description:
                - "RADIUS Request Ignored"
                type: str
            radius_table_full:
                description:
                - "RADIUS Request Dropped (Table Full)"
                type: str
            secret_not_configured_dropped:
                description:
                - "RADIUS Secret Not Configured Dropped"
                type: str
            ha_standby_dropped:
                description:
                - "HA Standby Dropped"
                type: str
            ipv6_prefix_length_mismatch:
                description:
                - "Framed IPV6 Prefix Length Mismatch"
                type: str
            invalid_key:
                description:
                - "Radius Request has Invalid Key Field"
                type: str
            smp_created:
                description:
                - "RADIUS SMP Created"
                type: str
            smp_deleted:
                description:
                - "RADIUS SMP Deleted"
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
    "accounting_interim_update",
    "accounting_on",
    "accounting_start",
    "accounting_stop",
    "attribute",
    "attribute_name",
    "disable_reply",
    "encrypted",
    "listen_port",
    "oper",
    "remote",
    "sampling_enable",
    "secret",
    "secret_string",
    "stats",
    "uuid",
    "vrid",
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
        'listen_port': {
            'type': 'int',
        },
        'remote': {
            'type': 'dict',
            'ip_list': {
                'type': 'list',
                'ip_list_name': {
                    'type': 'str',
                },
                'ip_list_secret': {
                    'type': 'bool',
                },
                'ip_list_secret_string': {
                    'type': 'str',
                },
                'ip_list_encrypted': {
                    'type': 'str',
                }
            }
        },
        'secret': {
            'type': 'bool',
        },
        'secret_string': {
            'type': 'str',
        },
        'encrypted': {
            'type': 'str',
        },
        'vrid': {
            'type': 'int',
        },
        'attribute': {
            'type': 'list',
            'attribute_value': {
                'type':
                'str',
                'choices': [
                    'inside-ipv6-prefix', 'inside-ip', 'inside-ipv6', 'imei',
                    'imsi', 'msisdn', 'custom1', 'custom2', 'custom3'
                ]
            },
            'prefix_length': {
                'type': 'str',
                'choices': ['32', '48', '64', '80', '96', '112']
            },
            'prefix_vendor': {
                'type': 'int',
            },
            'prefix_number': {
                'type': 'int',
            },
            'name': {
                'type': 'str',
            },
            'value': {
                'type': 'str',
                'choices': ['hexadecimal']
            },
            'custom_vendor': {
                'type': 'int',
            },
            'custom_number': {
                'type': 'int',
            },
            'vendor': {
                'type': 'int',
            },
            'number': {
                'type': 'int',
            }
        },
        'disable_reply': {
            'type': 'bool',
        },
        'accounting_start': {
            'type': 'str',
            'choices': ['ignore', 'append-entry', 'replace-entry']
        },
        'accounting_stop': {
            'type': 'str',
            'choices': ['ignore', 'delete-entry', 'delete-entry-and-sessions']
        },
        'accounting_interim_update': {
            'type': 'str',
            'choices': ['ignore', 'append-entry', 'replace-entry']
        },
        'accounting_on': {
            'type': 'str',
            'choices': ['ignore', 'delete-entries-using-attribute']
        },
        'attribute_name': {
            'type': 'str',
            'choices':
            ['msisdn', 'imei', 'imsi', 'custom1', 'custom2', 'custom3']
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
                    'all', 'msisdn-received', 'imei-received', 'imsi-received',
                    'custom-received', 'radius-request-received',
                    'radius-request-dropped', 'request-bad-secret-dropped',
                    'request-no-key-vap-dropped', 'request-malformed-dropped',
                    'request-ignored', 'radius-table-full',
                    'secret-not-configured-dropped', 'ha-standby-dropped',
                    'ipv6-prefix-length-mismatch', 'invalid-key',
                    'smp-created', 'smp-deleted', 'smp-mem-allocated',
                    'smp-mem-alloc-failed', 'smp-mem-freed', 'smp-in-rml',
                    'mem-allocated', 'mem-alloc-failed', 'mem-freed',
                    'ha-sync-create-sent', 'ha-sync-delete-sent',
                    'ha-sync-create-recv', 'ha-sync-delete-recv',
                    'acct-on-filters-full', 'acct-on-dup-request',
                    'ip-mismatch-delete', 'ip-add-race-drop',
                    'ha-sync-no-key-vap-dropped', 'inter-card-msg-fail-drop',
                    'radius-packets-redirected',
                    'radius-packets-redirect-fail-dropped',
                    'radius-packets-process-local',
                    'radius-packets-dropped-not-lo'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'radius_table_entries_list': {
                'type': 'list',
                'inside_ip': {
                    'type': 'str',
                },
                'inside_ipv6': {
                    'type': 'str',
                },
                'prefix_len': {
                    'type': 'int',
                },
                'msisdn': {
                    'type': 'str',
                },
                'imei': {
                    'type': 'str',
                },
                'imsi': {
                    'type': 'str',
                },
                'custom1_attr_value': {
                    'type': 'str',
                },
                'custom2_attr_value': {
                    'type': 'str',
                },
                'custom3_attr_value': {
                    'type': 'str',
                },
                'is_obsolete': {
                    'type': 'bool',
                }
            },
            'total_entries': {
                'type': 'int',
            },
            'custom_attr_name': {
                'type': 'str',
            },
            'custom_attr_value': {
                'type': 'str',
            },
            'starts_with': {
                'type': 'bool',
            },
            'case_insensitive': {
                'type': 'bool',
            }
        },
        'stats': {
            'type': 'dict',
            'msisdn_received': {
                'type': 'str',
            },
            'imei_received': {
                'type': 'str',
            },
            'imsi_received': {
                'type': 'str',
            },
            'custom_received': {
                'type': 'str',
            },
            'radius_request_received': {
                'type': 'str',
            },
            'radius_request_dropped': {
                'type': 'str',
            },
            'request_bad_secret_dropped': {
                'type': 'str',
            },
            'request_no_key_vap_dropped': {
                'type': 'str',
            },
            'request_malformed_dropped': {
                'type': 'str',
            },
            'request_ignored': {
                'type': 'str',
            },
            'radius_table_full': {
                'type': 'str',
            },
            'secret_not_configured_dropped': {
                'type': 'str',
            },
            'ha_standby_dropped': {
                'type': 'str',
            },
            'ipv6_prefix_length_mismatch': {
                'type': 'str',
            },
            'invalid_key': {
                'type': 'str',
            },
            'smp_created': {
                'type': 'str',
            },
            'smp_deleted': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/radius/server"

    f_dict = {}

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


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


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
    url_base = "/axapi/v3/system/radius/server"

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
        for k, v in payload["server"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["server"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["server"][k] = v
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
    payload = build_json("server", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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
