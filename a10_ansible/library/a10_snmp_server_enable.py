#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_snmp_server_enable
description:
    - Enable SNMP service
short_description: Configures A10 snmp.server.enable
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
    uuid:
        description:
        - "uuid of the object"
        required: False
    service:
        description:
        - "Enable SNMP service"
        required: False
    traps:
        description:
        - "Field traps"
        required: False
        suboptions:
            lldp:
                description:
                - "Enable lldp traps"
            all:
                description:
                - "Enable all SNMP traps"
            slb_change:
                description:
                - "Field slb_change"
            uuid:
                description:
                - "uuid of the object"
            lsn:
                description:
                - "Field lsn"
            vrrp_a:
                description:
                - "Field vrrp_a"
            snmp:
                description:
                - "Field snmp"
            system:
                description:
                - "Field system"
            ssl:
                description:
                - "Field ssl"
            vcs:
                description:
                - "Field vcs"
            routing:
                description:
                - "Field routing"
            gslb:
                description:
                - "Field gslb"
            slb:
                description:
                - "Field slb"
            network:
                description:
                - "Field network"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["service","traps","uuid",]

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
        uuid=dict(type='str',),
        service=dict(type='bool',),
        traps=dict(type='dict',lldp=dict(type='bool',),all=dict(type='bool',),slb_change=dict(type='dict',all=dict(type='bool',),resource_usage_warning=dict(type='bool',),uuid=dict(type='str',),ssl_cert_change=dict(type='bool',),ssl_cert_expire=dict(type='bool',),system_threshold=dict(type='bool',),server=dict(type='bool',),vip=dict(type='bool',),connection_resource_event=dict(type='bool',),server_port=dict(type='bool',),vip_port=dict(type='bool',)),uuid=dict(type='str',),lsn=dict(type='dict',all=dict(type='bool',),fixed_nat_port_mapping_file_change=dict(type='bool',),per_ip_port_usage_threshold=dict(type='bool',),uuid=dict(type='str',),total_port_usage_threshold=dict(type='bool',),max_port_threshold=dict(type='int',),max_ipport_threshold=dict(type='int',),traffic_exceeded=dict(type='bool',)),vrrp_a=dict(type='dict',active=dict(type='bool',),standby=dict(type='bool',),all=dict(type='bool',),uuid=dict(type='str',)),snmp=dict(type='dict',linkup=dict(type='bool',),all=dict(type='bool',),linkdown=dict(type='bool',),uuid=dict(type='str',)),system=dict(type='dict',all=dict(type='bool',),data_cpu_high=dict(type='bool',),uuid=dict(type='str',),power=dict(type='bool',),high_disk_use=dict(type='bool',),high_memory_use=dict(type='bool',),control_cpu_high=dict(type='bool',),file_sys_read_only=dict(type='bool',),low_temp=dict(type='bool',),high_temp=dict(type='bool',),sec_disk=dict(type='bool',),license_management=dict(type='bool',),start=dict(type='bool',),fan=dict(type='bool',),shutdown=dict(type='bool',),pri_disk=dict(type='bool',),syslog_severity_one=dict(type='bool',),tacacs_server_up_down=dict(type='bool',),smp_resource_event=dict(type='bool',),restart=dict(type='bool',),packet_drop=dict(type='bool',)),ssl=dict(type='dict',server_certificate_error=dict(type='bool',),uuid=dict(type='str',)),vcs=dict(type='dict',state_change=dict(type='bool',),uuid=dict(type='str',)),routing=dict(type='dict',bgp=dict(type='dict',bgpEstablishedNotification=dict(type='bool',),uuid=dict(type='str',),bgpBackwardTransNotification=dict(type='bool',)),isis=dict(type='dict',isisAuthenticationFailure=dict(type='bool',),uuid=dict(type='str',),isisProtocolsSupportedMismatch=dict(type='bool',),isisRejectedAdjacency=dict(type='bool',),isisMaxAreaAddressesMismatch=dict(type='bool',),isisCorruptedLSPDetected=dict(type='bool',),isisOriginatingLSPBufferSizeMismatch=dict(type='bool',),isisAreaMismatch=dict(type='bool',),isisLSPTooLargeToPropagate=dict(type='bool',),isisOwnLSPPurge=dict(type='bool',),isisSequenceNumberSkip=dict(type='bool',),isisDatabaseOverload=dict(type='bool',),isisAttemptToExceedMaxSequence=dict(type='bool',),isisIDLenMismatch=dict(type='bool',),isisAuthenticationTypeFailure=dict(type='bool',),isisVersionSkew=dict(type='bool',),isisManualAddressDrops=dict(type='bool',),isisAdjacencyChange=dict(type='bool',)),ospf=dict(type='dict',ospfLsdbOverflow=dict(type='bool',),uuid=dict(type='str',),ospfNbrStateChange=dict(type='bool',),ospfIfStateChange=dict(type='bool',),ospfVirtNbrStateChange=dict(type='bool',),ospfLsdbApproachingOverflow=dict(type='bool',),ospfIfAuthFailure=dict(type='bool',),ospfVirtIfAuthFailure=dict(type='bool',),ospfVirtIfConfigError=dict(type='bool',),ospfVirtIfRxBadPacket=dict(type='bool',),ospfTxRetransmit=dict(type='bool',),ospfVirtIfStateChange=dict(type='bool',),ospfIfConfigError=dict(type='bool',),ospfMaxAgeLsa=dict(type='bool',),ospfIfRxBadPacket=dict(type='bool',),ospfVirtIfTxRetransmit=dict(type='bool',),ospfOriginateLsa=dict(type='bool',))),gslb=dict(type='dict',all=dict(type='bool',),group=dict(type='bool',),uuid=dict(type='str',),zone=dict(type='bool',),site=dict(type='bool',),service_ip=dict(type='bool',)),slb=dict(type='dict',all=dict(type='bool',),server_down=dict(type='bool',),vip_port_connratelimit=dict(type='bool',),server_selection_failure=dict(type='bool',),service_group_down=dict(type='bool',),server_conn_limit=dict(type='bool',),service_group_member_up=dict(type='bool',),uuid=dict(type='str',),server_conn_resume=dict(type='bool',),service_up=dict(type='bool',),service_conn_limit=dict(type='bool',),gateway_up=dict(type='bool',),service_group_up=dict(type='bool',),application_buffer_limit=dict(type='bool',),vip_connratelimit=dict(type='bool',),vip_connlimit=dict(type='bool',),service_group_member_down=dict(type='bool',),service_down=dict(type='bool',),bw_rate_limit_exceed=dict(type='bool',),server_disabled=dict(type='bool',),server_up=dict(type='bool',),vip_port_connlimit=dict(type='bool',),vip_port_down=dict(type='bool',),bw_rate_limit_resume=dict(type='bool',),gateway_down=dict(type='bool',),vip_up=dict(type='bool',),vip_port_up=dict(type='bool',),vip_down=dict(type='bool',),service_conn_resume=dict(type='bool',)),network=dict(type='dict',trunk_port_threshold=dict(type='bool',),uuid=dict(type='str',)))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/snmp-server/enable"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/snmp-server/enable"

    f_dict = {}

    return url_base.format(**f_dict)

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["enable"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["enable"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["enable"][k] = v
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
    payload = build_json("enable", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("enable", module)
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
    if partition and not module.check_mode:
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