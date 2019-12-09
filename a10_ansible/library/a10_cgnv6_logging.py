#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_logging
description:
    - CGNV6 Logging Statistics
short_description: Configures A10 cgnv6.logging
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
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    tcp_svr_status:
        description:
        - "Field tcp_svr_status"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            tcp_port_overloading_allocated:
                description:
                - "TCP Port Overloading Allocated"
            tcp_session_deleted:
                description:
                - "TCP Session Deleted"
            gre_session_created:
                description:
                - "GRE Session Created"
            icmpv6_resource_freed:
                description:
                - "ICMPV6 Resource Freed"
            icmpv6_session_created:
                description:
                - "ICMPV6 Session Created"
            tcp_port_allocated:
                description:
                - "TCP Port Allocated"
            udp_port_overloading_freed:
                description:
                - "UDP Port Overloading Freed"
            tcp_session_created:
                description:
                - "TCP Session Created"
            log_sent:
                description:
                - "Log Packets Sent"
            udp_port_allocated:
                description:
                - "UDP Port Allocated"
            fixed_nat_periodic_config_logged:
                description:
                - "Fixed NAT Disabled Config Logs Sent"
            udp_session_created:
                description:
                - "UDP Session Created"
            gre_resource_allocated:
                description:
                - "GRE Resource Allocated"
            udp_port_batch_freed:
                description:
                - "UDP Port Batch Freed"
            esp_session_deleted:
                description:
                - "ESP Session Deleted"
            fixed_nat_disable_config_logged:
                description:
                - "Fixed NAT Periodic Configs Logged"
            esp_resource_allocated:
                description:
                - "ESP Resource Allocated"
            fixed_nat_periodic_config_logs_sent:
                description:
                - "Fixed NAT Disabled Configs Logged"
            http_request_logged:
                description:
                - "HTTP Request Logged"
            enhanced_user_log:
                description:
                - "Enhanced User Log"
            icmp_resource_allocated:
                description:
                - "ICMP Resource Allocated"
            esp_session_created:
                description:
                - "ESP Session Created"
            icmp_resource_freed:
                description:
                - "ICMP Resource Freed"
            fixed_nat_interim_updated:
                description:
                - "Fixed NAT Interim Updated"
            icmpv6_session_deleted:
                description:
                - "ICMPV6 Session Deleted"
            udp_port_batch_interim_updated:
                description:
                - "UDP Port Batch Interim Updated"
            tcp_port_overloading_freed:
                description:
                - "TCP Port Overloading Freed"
            icmp_session_deleted:
                description:
                - "ICMP Session Deleted"
            gre_resource_freed:
                description:
                - "GRE Resource Freed"
            gre_session_deleted:
                description:
                - "GRE Session Deleted"
            udp_port_overloading_allocated:
                description:
                - "UDP Port Overloading Allocated"
            fixed_nat_user_ports:
                description:
                - "Fixed NAT Inside User Port Mapping"
            tcp_port_freed:
                description:
                - "TCP Port Freed"
            esp_resource_freed:
                description:
                - "ESP Resource Freed"
            reduced_logs_by_destination:
                description:
                - "Reduced Logs by Destination Protocol and Port"
            icmp_session_created:
                description:
                - "ICMP Session Created"
            conn_tcp_established:
                description:
                - "TCP Connection Established"
            fixed_nat_disable_config_logs_sent:
                description:
                - "Fixed NAT Periodic Config Logs Sent"
            udp_port_batch_allocated:
                description:
                - "UDP Port Batch Allocated"
            udp_port_freed:
                description:
                - "UDP Port Freed"
            conn_tcp_dropped:
                description:
                - "TCP Connection Lost"
            tcp_port_batch_freed:
                description:
                - "TCP Port Batch Freed"
            log_dropped:
                description:
                - "Log Packets Dropped"
            icmpv6_resource_allocated:
                description:
                - "ICMPV6 Resource Allocated"
            tcp_port_batch_interim_updated:
                description:
                - "TCP Port Batch Interim Updated"
            udp_session_deleted:
                description:
                - "UDP Session Deleted"
            tcp_port_batch_allocated:
                description:
                - "TCP Port Batch Allocated"
    uuid:
        description:
        - "uuid of the object"
        required: False
    source_address:
        description:
        - "Field source_address"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    nat_quota_exceeded:
        description:
        - "Field nat_quota_exceeded"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            level:
                description:
                - "'warning'= Log level Warning (Default); 'critical'= Log level Critical; 'notice'= Log level Notice; "
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'tcp-session-created'= TCP Session Created; 'tcp-session-deleted'= TCP Session Deleted; 'tcp-port-allocated'= TCP Port Allocated; 'tcp-port-freed'= TCP Port Freed; 'tcp-port-batch-allocated'= TCP Port Batch Allocated; 'tcp-port-batch-freed'= TCP Port Batch Freed; 'udp-session-created'= UDP Session Created; 'udp-session-deleted'= UDP Session Deleted; 'udp-port-allocated'= UDP Port Allocated; 'udp-port-freed'= UDP Port Freed; 'udp-port-batch-allocated'= UDP Port Batch Allocated; 'udp-port-batch-freed'= UDP Port Batch Freed; 'icmp-session-created'= ICMP Session Created; 'icmp-session-deleted'= ICMP Session Deleted; 'icmp-resource-allocated'= ICMP Resource Allocated; 'icmp-resource-freed'= ICMP Resource Freed; 'icmpv6-session-created'= ICMPV6 Session Created; 'icmpv6-session-deleted'= ICMPV6 Session Deleted; 'icmpv6-resource-allocated'= ICMPV6 Resource Allocated; 'icmpv6-resource-freed'= ICMPV6 Resource Freed; 'gre-session-created'= GRE Session Created; 'gre-session-deleted'= GRE Session Deleted; 'gre-resource-allocated'= GRE Resource Allocated; 'gre-resource-freed'= GRE Resource Freed; 'esp-session-created'= ESP Session Created; 'esp-session-deleted'= ESP Session Deleted; 'esp-resource-allocated'= ESP Resource Allocated; 'esp-resource-freed'= ESP Resource Freed; 'fixed-nat-user-ports'= Fixed NAT Inside User Port Mapping; 'fixed-nat-disable-config-logged'= Fixed NAT Periodic Configs Logged; 'fixed-nat-disable-config-logs-sent'= Fixed NAT Periodic Config Logs Sent; 'fixed-nat-periodic-config-logs-sent'= Fixed NAT Disabled Configs Logged; 'fixed-nat-periodic-config-logged'= Fixed NAT Disabled Config Logs Sent; 'fixed-nat-interim-updated'= Fixed NAT Interim Updated; 'enhanced-user-log'= Enhanced User Log; 'log-sent'= Log Packets Sent; 'log-dropped'= Log Packets Dropped; 'conn-tcp-established'= TCP Connection Established; 'conn-tcp-dropped'= TCP Connection Lost; 'tcp-port-overloading-allocated'= TCP Port Overloading Allocated; 'tcp-port-overloading-freed'= TCP Port Overloading Freed; 'udp-port-overloading-allocated'= UDP Port Overloading Allocated; 'udp-port-overloading-freed'= UDP Port Overloading Freed; 'http-request-logged'= HTTP Request Logged; 'reduced-logs-by-destination'= Reduced Logs by Destination Protocol and Port; 'out-of-buffers'= Out of Buffers; 'add-msg-failed'= Add Message to Buffer Failed; 'rtsp-port-allocated'= RTSP UDP Port Allocated; 'rtsp-port-freed'= RTSP UDP Port Freed; 'conn-tcp-create-failed'= TCP Connection Failed; 'ipv4-frag-applied'= IPv4 Fragmentation Applied; 'ipv4-frag-failed'= IPv4 Fragmentation Failed; 'ipv6-frag-applied'= IPv6 Fragmentation Applied; 'ipv6-frag-failed'= IPv6 Fragmentation Failed; 'interim-update-scheduled'= Port Allocation Interim Update Scheduled; 'interim-update-schedule-failed'= Port Allocation Interim Update Failed; 'interim-update-terminated'= Port Allocation Interim Update Terminated; 'interim-update-memory-freed'= Port Allocation Interim Update Memory Freed; 'interim-update-no-buff-retried'= Port Allocation Interim Update Memory Freed; 'tcp-port-batch-interim-updated'= TCP Port Batch Interim Updated; 'udp-port-batch-interim-updated'= UDP Port Batch Interim Updated; 'port-block-accounting-freed'= Port Allocation Accounting Freed; 'port-block-accounting-allocated'= Port Allocation Accounting Allocated; 'log-message-too-long'= Log message too long; 'http-out-of-order-dropped'= HTTP out-of-order dropped; 'http-alloc-failed'= HTTP Request Info Allocation Failed; 'http-frag-merge-failed-dropped'= HTTP frag merge failed dropped; 'http-malloc'= HTTP mem allocate; 'http-mfree'= HTTP mem free; 'http-spm-alloc-type0'= HTTP Conn SPM Type 0 allocate; 'http-spm-alloc-type1'= HTTP Conn SPM Type 1 allocate; 'http-spm-alloc-type2'= HTTP Conn SPM Type 2 allocate; 'http-spm-alloc-type3'= HTTP Conn SPM Type 3 allocate; 'http-spm-alloc-type4'= HTTP Conn SPM Type 4 allocate; 'http-spm-free-type0'= HTTP Conn SPM Type 0 free; 'http-spm-free-type1'= HTTP Conn SPM Type 1 free; 'http-spm-free-type2'= HTTP Conn SPM Type 2 free; 'http-spm-free-type3'= HTTP Conn SPM Type 3 free; 'http-spm-free-type4'= HTTP Conn SPM Type 4 free; "
    nat_resource_exhausted:
        description:
        - "Field nat_resource_exhausted"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            level:
                description:
                - "'warning'= Log level Warning; 'critical'= Log level Critical (Default); 'notice'= Log level Notice; "


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["nat_quota_exceeded","nat_resource_exhausted","sampling_enable","source_address","stats","tcp_svr_status","uuid",]

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
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        tcp_svr_status=dict(type='dict',uuid=dict(type='str',)),
        stats=dict(type='dict',tcp_port_overloading_allocated=dict(type='str',),tcp_session_deleted=dict(type='str',),gre_session_created=dict(type='str',),icmpv6_resource_freed=dict(type='str',),icmpv6_session_created=dict(type='str',),tcp_port_allocated=dict(type='str',),udp_port_overloading_freed=dict(type='str',),tcp_session_created=dict(type='str',),log_sent=dict(type='str',),udp_port_allocated=dict(type='str',),fixed_nat_periodic_config_logged=dict(type='str',),udp_session_created=dict(type='str',),gre_resource_allocated=dict(type='str',),udp_port_batch_freed=dict(type='str',),esp_session_deleted=dict(type='str',),fixed_nat_disable_config_logged=dict(type='str',),esp_resource_allocated=dict(type='str',),fixed_nat_periodic_config_logs_sent=dict(type='str',),http_request_logged=dict(type='str',),enhanced_user_log=dict(type='str',),icmp_resource_allocated=dict(type='str',),esp_session_created=dict(type='str',),icmp_resource_freed=dict(type='str',),fixed_nat_interim_updated=dict(type='str',),icmpv6_session_deleted=dict(type='str',),udp_port_batch_interim_updated=dict(type='str',),tcp_port_overloading_freed=dict(type='str',),icmp_session_deleted=dict(type='str',),gre_resource_freed=dict(type='str',),gre_session_deleted=dict(type='str',),udp_port_overloading_allocated=dict(type='str',),fixed_nat_user_ports=dict(type='str',),tcp_port_freed=dict(type='str',),esp_resource_freed=dict(type='str',),reduced_logs_by_destination=dict(type='str',),icmp_session_created=dict(type='str',),conn_tcp_established=dict(type='str',),fixed_nat_disable_config_logs_sent=dict(type='str',),udp_port_batch_allocated=dict(type='str',),udp_port_freed=dict(type='str',),conn_tcp_dropped=dict(type='str',),tcp_port_batch_freed=dict(type='str',),log_dropped=dict(type='str',),icmpv6_resource_allocated=dict(type='str',),tcp_port_batch_interim_updated=dict(type='str',),udp_session_deleted=dict(type='str',),tcp_port_batch_allocated=dict(type='str',)),
        uuid=dict(type='str',),
        source_address=dict(type='dict',uuid=dict(type='str',)),
        nat_quota_exceeded=dict(type='dict',uuid=dict(type='str',),level=dict(type='str',choices=['warning','critical','notice'])),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','tcp-session-created','tcp-session-deleted','tcp-port-allocated','tcp-port-freed','tcp-port-batch-allocated','tcp-port-batch-freed','udp-session-created','udp-session-deleted','udp-port-allocated','udp-port-freed','udp-port-batch-allocated','udp-port-batch-freed','icmp-session-created','icmp-session-deleted','icmp-resource-allocated','icmp-resource-freed','icmpv6-session-created','icmpv6-session-deleted','icmpv6-resource-allocated','icmpv6-resource-freed','gre-session-created','gre-session-deleted','gre-resource-allocated','gre-resource-freed','esp-session-created','esp-session-deleted','esp-resource-allocated','esp-resource-freed','fixed-nat-user-ports','fixed-nat-disable-config-logged','fixed-nat-disable-config-logs-sent','fixed-nat-periodic-config-logs-sent','fixed-nat-periodic-config-logged','fixed-nat-interim-updated','enhanced-user-log','log-sent','log-dropped','conn-tcp-established','conn-tcp-dropped','tcp-port-overloading-allocated','tcp-port-overloading-freed','udp-port-overloading-allocated','udp-port-overloading-freed','http-request-logged','reduced-logs-by-destination','out-of-buffers','add-msg-failed','rtsp-port-allocated','rtsp-port-freed','conn-tcp-create-failed','ipv4-frag-applied','ipv4-frag-failed','ipv6-frag-applied','ipv6-frag-failed','interim-update-scheduled','interim-update-schedule-failed','interim-update-terminated','interim-update-memory-freed','interim-update-no-buff-retried','tcp-port-batch-interim-updated','udp-port-batch-interim-updated','port-block-accounting-freed','port-block-accounting-allocated','log-message-too-long','http-out-of-order-dropped','http-alloc-failed','http-frag-merge-failed-dropped','http-malloc','http-mfree','http-spm-alloc-type0','http-spm-alloc-type1','http-spm-alloc-type2','http-spm-alloc-type3','http-spm-alloc-type4','http-spm-free-type0','http-spm-free-type1','http-spm-free-type2','http-spm-free-type3','http-spm-free-type4'])),
        nat_resource_exhausted=dict(type='dict',uuid=dict(type='str',),level=dict(type='str',choices=['warning','critical','notice']))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/logging"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/logging"

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

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["logging"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["logging"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["logging"][k] = v
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
    payload = build_json("logging", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

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
    a10_partition = module.params["a10_partition"]

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
    if a10_partition:
        module.client.activate_partition(a10_partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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