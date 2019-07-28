#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
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
                - "Enable LSN trap when NAT total port usage reaches the threshold (default 655350000)"
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
            license_management:
                description:
                - "Enable system license management traps"
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

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["all","gslb","lldp","lsn","network","routing","slb","slb_change","snmp","ssl","system","uuid","vcs","vrrp_a",]

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
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        lldp=dict(type='bool',),
        all=dict(type='bool',),
        slb_change=dict(type='dict',all=dict(type='bool',),resource_usage_warning=dict(type='bool',),uuid=dict(type='str',),ssl_cert_change=dict(type='bool',),ssl_cert_expire=dict(type='bool',),system_threshold=dict(type='bool',),server=dict(type='bool',),vip=dict(type='bool',),connection_resource_event=dict(type='bool',),server_port=dict(type='bool',),vip_port=dict(type='bool',)),
        uuid=dict(type='str',),
        lsn=dict(type='dict',all=dict(type='bool',),fixed_nat_port_mapping_file_change=dict(type='bool',),per_ip_port_usage_threshold=dict(type='bool',),uuid=dict(type='str',),total_port_usage_threshold=dict(type='bool',),max_port_threshold=dict(type='int',),max_ipport_threshold=dict(type='int',),traffic_exceeded=dict(type='bool',)),
        vrrp_a=dict(type='dict',active=dict(type='bool',),standby=dict(type='bool',),all=dict(type='bool',),uuid=dict(type='str',)),
        snmp=dict(type='dict',linkup=dict(type='bool',),all=dict(type='bool',),linkdown=dict(type='bool',),uuid=dict(type='str',)),
        system=dict(type='dict',all=dict(type='bool',),data_cpu_high=dict(type='bool',),uuid=dict(type='str',),power=dict(type='bool',),high_disk_use=dict(type='bool',),high_memory_use=dict(type='bool',),control_cpu_high=dict(type='bool',),file_sys_read_only=dict(type='bool',),low_temp=dict(type='bool',),high_temp=dict(type='bool',),sec_disk=dict(type='bool',),start=dict(type='bool',),fan=dict(type='bool',),shutdown=dict(type='bool',),pri_disk=dict(type='bool',),license_management=dict(type='bool',),tacacs_server_up_down=dict(type='bool',),smp_resource_event=dict(type='bool',),restart=dict(type='bool',),packet_drop=dict(type='bool',)),
        ssl=dict(type='dict',server_certificate_error=dict(type='bool',),uuid=dict(type='str',)),
        vcs=dict(type='dict',state_change=dict(type='bool',),uuid=dict(type='str',)),
        routing=dict(type='dict',bgp=dict(type='dict',bgpEstablishedNotification=dict(type='bool',),uuid=dict(type='str',),bgpBackwardTransNotification=dict(type='bool',)),isis=dict(type='dict',isisAuthenticationFailure=dict(type='bool',),uuid=dict(type='str',),isisProtocolsSupportedMismatch=dict(type='bool',),isisRejectedAdjacency=dict(type='bool',),isisMaxAreaAddressesMismatch=dict(type='bool',),isisCorruptedLSPDetected=dict(type='bool',),isisOriginatingLSPBufferSizeMismatch=dict(type='bool',),isisAreaMismatch=dict(type='bool',),isisLSPTooLargeToPropagate=dict(type='bool',),isisOwnLSPPurge=dict(type='bool',),isisSequenceNumberSkip=dict(type='bool',),isisDatabaseOverload=dict(type='bool',),isisAttemptToExceedMaxSequence=dict(type='bool',),isisIDLenMismatch=dict(type='bool',),isisAuthenticationTypeFailure=dict(type='bool',),isisVersionSkew=dict(type='bool',),isisManualAddressDrops=dict(type='bool',),isisAdjacencyChange=dict(type='bool',)),ospf=dict(type='dict',ospfLsdbOverflow=dict(type='bool',),uuid=dict(type='str',),ospfNbrStateChange=dict(type='bool',),ospfIfStateChange=dict(type='bool',),ospfVirtNbrStateChange=dict(type='bool',),ospfLsdbApproachingOverflow=dict(type='bool',),ospfIfAuthFailure=dict(type='bool',),ospfVirtIfAuthFailure=dict(type='bool',),ospfVirtIfConfigError=dict(type='bool',),ospfVirtIfRxBadPacket=dict(type='bool',),ospfTxRetransmit=dict(type='bool',),ospfVirtIfStateChange=dict(type='bool',),ospfIfConfigError=dict(type='bool',),ospfMaxAgeLsa=dict(type='bool',),ospfIfRxBadPacket=dict(type='bool',),ospfVirtIfTxRetransmit=dict(type='bool',),ospfOriginateLsa=dict(type='bool',))),
        gslb=dict(type='dict',all=dict(type='bool',),group=dict(type='bool',),uuid=dict(type='str',),zone=dict(type='bool',),site=dict(type='bool',),service_ip=dict(type='bool',)),
        slb=dict(type='dict',all=dict(type='bool',),server_down=dict(type='bool',),vip_port_connratelimit=dict(type='bool',),server_selection_failure=dict(type='bool',),service_group_down=dict(type='bool',),server_conn_limit=dict(type='bool',),service_group_member_up=dict(type='bool',),uuid=dict(type='str',),server_conn_resume=dict(type='bool',),service_up=dict(type='bool',),service_conn_limit=dict(type='bool',),gateway_up=dict(type='bool',),service_group_up=dict(type='bool',),application_buffer_limit=dict(type='bool',),vip_connratelimit=dict(type='bool',),vip_connlimit=dict(type='bool',),service_group_member_down=dict(type='bool',),service_down=dict(type='bool',),bw_rate_limit_exceed=dict(type='bool',),server_disabled=dict(type='bool',),server_up=dict(type='bool',),vip_port_connlimit=dict(type='bool',),vip_port_down=dict(type='bool',),bw_rate_limit_resume=dict(type='bool',),gateway_down=dict(type='bool',),vip_up=dict(type='bool',),vip_port_up=dict(type='bool',),vip_down=dict(type='bool',),service_conn_resume=dict(type='bool',)),
        network=dict(type='dict',trunk_port_threshold=dict(type='bool',),uuid=dict(type='str',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/snmp-server/enable/traps"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/snmp-server/enable/traps"

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
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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
    payload = build_json("traps", module)
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

def update(module, result, existing_config):
    payload = build_json("traps", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("traps", module)
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
        message=""
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
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if partition:
        module.client.activate_partition(partition)

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