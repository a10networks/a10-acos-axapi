#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_netflow_template
description:
    - IPFIX Custom Template
short_description: Configures A10 netflow.template
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
    information_element_blk:
        description:
        - "Field information_element_blk"
        required: False
        suboptions:
            information_element:
                description:
                - "'fwd-tuple-vnp-id'= Session forward tuple partition id (ID= 33028); 'rev-tuple-vnp-id'= Session reverse tuple partition id (ID= 33029); 'source-ipv4-address'= IPv4 source address in the IP packet header (ID= 8); 'dest-ipv4-address'= IPv4 destination address in the IP packet header (ID= 12); 'source-ipv6-address'= IPv6 source address in the IP packet header (ID= 27); 'dest-ipv6-address'= IPv6 destination address in the IP packet header (ID=28); 'post-nat-source-ipv4-address'= IPv4 natted source address (ID= 225); 'post-nat-dest-ipv4-address'= IPv4 natted destination address(ID= 226); 'post-nat-source-ipv6-address'= IPv6 natted source address (ID= 281); 'post-nat-dest-ipv6-address'= IPv6 natted destination address (ID= 282); 'source-port'= Source port identifier in the transport header (ID= 7); 'dest-port'= Destination port identifier in the transport header (ID= 11); 'post-nat-source-port'= L4 natted source port(ID= 227); 'post-nat-dest-port'= L4 natted destination port (ID= 228); 'fwd-tuple-type'= Session forward tuple type (ID= 33024); 'rev-tuple-type'= Session reverse tuple type (ID= 33025); 'ip-proto'= Value of the protocol number in the IP packet header (ID= 4); 'flow-direction'= Flow direction= 0=inbound(To an outside interface)/1=outbound(To an inside interface) (ID= 61); 'tcp-control-bits'= Cumulative of all the TCP flags seen for this flow (ID= 6); 'fwd-bytes'= Incoming bytes associated with an IP Flow (ID= 1); 'fwd-packets'= Incoming packets associated with an IP Flow (ID= 2); 'rev-bytes'= Delta bytes in reverse direction of bidirectional flow record (ID= 32769); 'rev-packets'= Delta packets in reverse direction of bidirectional flow record (ID= 32770); 'in-port'= Incoming interface port (ID= 10); 'out-port'= Outcoming interface port (ID= 14); 'in-interface'= Incoming interface name e.g. ethernet 0 (ID= 82); 'out-interface'= Outcoming interface name e.g. ethernet 0 (ID= 32850); 'port-range-start'= Port number identifying the start of a range of ports (ID= 361); 'port-range-end'= Port number identifying the end of a range of ports (ID= 362); 'port-range-step-size'= Step size in a port range (ID= 363); 'port-range-num-ports'= Number of ports in a port range (ID= 364); 'rule-name'= Rule Name (ID= 33034); 'rule-set-name'= Rule-Set Name (ID= 33035); 'fw-source-zone'= Firewall Source Zone Name (ID= 33036); 'fw-dest-zone'= Firewall Dest Zone Name (ID= 33037); 'application-id'= Application ID (ID= 95); 'radius-imsi'= Radius Attribute IMSI (ID= 455); 'radius-msisdn'= Radius Attribute MSISDN (ID= 456); 'radius-imei'= Radius Attribute IMEI (ID= 33030); 'radius-custom1'= Radius Attribute Custom 1 (ID= 33031); 'radius-custom2'= Radius Attribute Custom 2(ID= 33032); 'radius-custom3'= Radius Attribute Custom 3 (ID=33033); 'flow-start-msec'= The absolute timestamp of the first packet of the flow (ID= 152); 'flow-duration-msec'= Difference in time between the first observed packet of this flow and the last observed packet of this flow (4 bytes) (ID= 161); 'flow-duration-msec-64'= Difference in time between the first observed packet of this flow and the last observed packet of this flow (8 bytes) (ID= 33039); 'nat-event'= Indicates a NAT event (ID= 230); 'fw-event'= Indicates a FW session event(ID= 233); 'fw-deny-reset-event'= Indicates a FW deny/reset event (ID= 33038); 'cgn-flow-direction'= Flow direction= 0=inbound(To an outside interface)/1=outbound(To an inside interface)/2=hairpin(From an inside interface to an inside interface) (ID= 33040); "
    ipfix_template_id:
        description:
        - "Custom IPFIX Template ID"
        required: False
    name:
        description:
        - "IPFIX CUSTOM Template Name"
        required: True
    user_tag:
        description:
        - "Customized tag"
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
AVAILABLE_PROPERTIES = ["information_element_blk","ipfix_template_id","name","user_tag","uuid",]

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
        information_element_blk=dict(type='list',information_element=dict(type='str',choices=['fwd-tuple-vnp-id','rev-tuple-vnp-id','source-ipv4-address','dest-ipv4-address','source-ipv6-address','dest-ipv6-address','post-nat-source-ipv4-address','post-nat-dest-ipv4-address','post-nat-source-ipv6-address','post-nat-dest-ipv6-address','source-port','dest-port','post-nat-source-port','post-nat-dest-port','fwd-tuple-type','rev-tuple-type','ip-proto','flow-direction','tcp-control-bits','fwd-bytes','fwd-packets','rev-bytes','rev-packets','in-port','out-port','in-interface','out-interface','port-range-start','port-range-end','port-range-step-size','port-range-num-ports','rule-name','rule-set-name','fw-source-zone','fw-dest-zone','application-id','radius-imsi','radius-msisdn','radius-imei','radius-custom1','radius-custom2','radius-custom3','flow-start-msec','flow-duration-msec','flow-duration-msec-64','nat-event','fw-event','fw-deny-reset-event','cgn-flow-direction'])),
        ipfix_template_id=dict(type='int',),
        name=dict(type='str',required=True,),
        user_tag=dict(type='str',),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/netflow/template/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/netflow/template/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("template", module)
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
    payload = build_json("template", module)
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
    payload = build_json("template", module)
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