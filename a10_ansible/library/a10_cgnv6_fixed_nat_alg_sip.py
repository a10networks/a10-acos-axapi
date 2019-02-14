#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_fixed_nat_alg_sip
description:
    - Change Fixed NAT SIP ALG Settings
short_description: Configures A10 cgnv6.fixed.nat.alg.sip
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'method-register'= SIP Method REGISTER; 'method-invite'= SIP Method INVITE; 'method-ack'= SIP Method ACK; 'method-cancel'= SIP Method CANCEL; 'method-bye'= SIP Method BYE; 'method-options'= SIP Method OPTIONS; 'method-prack'= SIP Method PRACK; 'method-subscribe'= SIP Method SUBSCRIBE; 'method-notify'= SIP Method NOTIFY; 'method-publish'= SIP Method PUBLISH; 'method-info'= SIP Method INFO; 'method-refer'= SIP Method REFER; 'method-message'= SIP Method MESSAGE; 'method-update'= SIP Method UPDATE; 'method-unknown'= SIP Method UNKNOWN; 'parse-error'= SIP Message Parse Error; 'req-uri-op-failrue'= SIP Operate Request Uri Failure; 'via-hdr-op-failrue'= SIP Operate Via Header Failure; 'contact-hdr-op-failrue'= SIP Operate Contact Header Failure; 'from-hdr-op-failrue'= SIP Operate From Header Failure; 'to-hdr-op-failrue'= SIP Operate To Header Failure; 'route-hdr-op-failrue'= SIP Operate Route Header Failure; 'record-route-hdr-op-failrue'= SIP Operate Record-Route Header Failure; 'content-length-hdr-op-failrue'= SIP Operate Content-Length Failure; 'third-party-registration'= SIP Third-Party Registration; 'conn-ext-creation-failure'= SIP Create Connection Extension Failure; 'alloc-contact-port-failure'= SIP Alloc Contact Port Failure; 'outside-contact-port-mismatch'= SIP Outside Contact Port Mismatch NAT Port; 'inside-contact-port-mismatch'= SIP Inside Contact Port Mismatch; 'third-party-sdp'= SIP Third-Party SDP; 'sdp-process-candidate-failure'= SIP Operate SDP Media Candidate Attribute Failure; 'sdp-op-failure'= SIP Operate SDP Failure; 'sdp-alloc-port-map-success'= SIP Alloc SDP Port Map Success; 'sdp-alloc-port-map-failure'= SIP Alloc SDP Port Map Failure; 'modify-failure'= SIP Message Modify Failure; 'rewrite-failure'= SIP Message Rewrite Failure; 'tcp-out-of-order-drop'= TCP Out-of-Order Drop; 'smp-conn-alloc-failure'= SMP Helper Conn Alloc Failure; 'helper-found'= SMP Helper Conn Found; 'helper-created'= SMP Helper Conn Created; 'helper-deleted'= SMP Helper Conn Already Deleted; 'helper-freed'= SMP Helper Conn Freed; 'helper-failure'= SMP Helper Failure; "
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
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

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
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        state=dict(type='str', default="present", choices=["present", "absent"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','method-register','method-invite','method-ack','method-cancel','method-bye','method-options','method-prack','method-subscribe','method-notify','method-publish','method-info','method-refer','method-message','method-update','method-unknown','parse-error','req-uri-op-failrue','via-hdr-op-failrue','contact-hdr-op-failrue','from-hdr-op-failrue','to-hdr-op-failrue','route-hdr-op-failrue','record-route-hdr-op-failrue','content-length-hdr-op-failrue','third-party-registration','conn-ext-creation-failure','alloc-contact-port-failure','outside-contact-port-mismatch','inside-contact-port-mismatch','third-party-sdp','sdp-process-candidate-failure','sdp-op-failure','sdp-alloc-port-map-success','sdp-alloc-port-map-failure','modify-failure','rewrite-failure','tcp-out-of-order-drop','smp-conn-alloc-failure','helper-found','helper-created','helper-deleted','helper-freed','helper-failure'])),
        uuid=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/fixed-nat/alg/sip"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/fixed-nat/alg/sip"
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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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
    payload = build_json("sip", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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
    payload = build_json("sip", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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