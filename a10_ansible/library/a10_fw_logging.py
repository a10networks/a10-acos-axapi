#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_fw_logging
description:
    - Bind a logging template to firewall
short_description: Configures A10 fw.logging
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'log_message_sent'= Log Packet Sent; 'log_type_reset'= Log Event Type Reset; 'log_type_deny'= Log Event Type Deny; 'log_type_session_closed'= Log Event Type Session Close; 'log_type_session_opened'= Log Event Type Session Open; 'rule_not_logged'= Firewall Rule Not Logged; 'log-dropped'= Log Packets Dropped; 'tcp-session-created'= TCP Session Created; 'tcp-session-deleted'= TCP Session Deleted; 'udp-session-created'= UDP Session Created; 'udp-session-deleted'= UDP Session Deleted; 'icmp-session-deleted'= ICMP Session Deleted; 'icmp-session-created'= ICMP Session Created; 'icmpv6-session-deleted'= ICMPV6 Session Deleted; 'icmpv6-session-created'= ICMPV6 Session Created; 'other-session-deleted'= Other Session Deleted; 'other-session-created'= Other Session Created; 'http-request-logged'= HTTP Request Logged; 'http-logging-invalid-format'= HTTP Logging Invalid Format Error; 'dcmsg_permit'= Dcmsg Permit; 'alg_override_permit'= Alg Override Permit; 'template_error'= Template Error; 'ipv4-frag-applied'= IPv4 Fragmentation Applied; 'ipv4-frag-failed'= IPv4 Fragmentation Failed; 'ipv6-frag-applied'= IPv6 Fragmentation Applied; 'ipv6-frag-failed'= IPv6 Fragmentation Failed; 'out-of-buffers'= Out of Buffers; 'add-msg-failed'= Add Message to Buffer Failed; 'tcp-logging-conn-established'= TCP Logging Conn Established; 'tcp-logging-conn-create-failed'= TCP Logging Conn Create Failed; 'tcp-logging-conn-dropped'= TCP Logging Conn Dropped; 'log-message-too-long'= Log message too long; 'http-out-of-order-dropped'= HTTP out-of-order dropped; 'http-alloc-failed'= HTTP Request Info Allocation Failed; 'sctp-session-created'= SCTP Session Created; 'sctp-session-deleted'= SCTP Session Deleted; 'log_type_sctp_inner_proto_filter'= Log Event Type SCTP Inner Proto Filter; 'log_type_gtp_message_filtering'= Log Event Type GTP Message Filtering; 'log_type_gtp_apn_filtering'= Log Event Type GTP Apn Filtering; 'tcp-logging-port-allocated'= TCP Logging Port Allocated; 'tcp-logging-port-freed'= TCP Logging Port Freed; 'tcp-logging-port-allocation-failed'= TCP Logging Port Allocation Failed; 'log_type_gtp_invalid_teid'= Log Event Type GTP Invalid TEID; 'log_gtp_type_reserved_ie_present'= Log Event Type GTP Reserved Information Element Present; 'log_type_gtp_mandatory_ie_missing'= Log Event Type GTP Mandatory Information Element Missing; "
    name:
        description:
        - "Logging Template Name"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["name","sampling_enable","uuid",]

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
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','log_message_sent','log_type_reset','log_type_deny','log_type_session_closed','log_type_session_opened','rule_not_logged','log-dropped','tcp-session-created','tcp-session-deleted','udp-session-created','udp-session-deleted','icmp-session-deleted','icmp-session-created','icmpv6-session-deleted','icmpv6-session-created','other-session-deleted','other-session-created','http-request-logged','http-logging-invalid-format','dcmsg_permit','alg_override_permit','template_error','ipv4-frag-applied','ipv4-frag-failed','ipv6-frag-applied','ipv6-frag-failed','out-of-buffers','add-msg-failed','tcp-logging-conn-established','tcp-logging-conn-create-failed','tcp-logging-conn-dropped','log-message-too-long','http-out-of-order-dropped','http-alloc-failed','sctp-session-created','sctp-session-deleted','log_type_sctp_inner_proto_filter','log_type_gtp_message_filtering','log_type_gtp_apn_filtering','tcp-logging-port-allocated','tcp-logging-port-freed','tcp-logging-port-allocation-failed','log_type_gtp_invalid_teid','log_gtp_type_reserved_ie_present','log_type_gtp_mandatory_ie_missing'])),
        name=dict(type='str',),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/logging"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/logging"

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
        return False

def create(module, result):
    payload = build_json("logging", module)
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
    payload = build_json("logging", module)
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
    payload = build_json("logging", module)
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
    if partition:
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
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()