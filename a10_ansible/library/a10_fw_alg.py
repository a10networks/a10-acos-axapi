#!/usr/bin/python
# -*- coding: UTF-8 -*-
# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_fw_alg
description:
    - Configure ALG
short_description: Configures A10 fw.alg
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
    ftp:
        description:
        - "Field ftp"
        required: False
        suboptions:
            default_port_disable:
                description:
                - "'default-port-disable'= Disable FTP ALG default port 21; "
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    sip:
        description:
        - "Field sip"
        required: False
        suboptions:
            default_port_disable:
                description:
                - "'default-port-disable'= Disable SIP ALG default port 5060; "
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False
    pptp:
        description:
        - "Field pptp"
        required: False
        suboptions:
            default_port_disable:
                description:
                - "'default-port-disable'= Disable PPTP ALG default port 1723; "
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    rtsp:
        description:
        - "Field rtsp"
        required: False
        suboptions:
            default_port_disable:
                description:
                - "'default-port-disable'= Disable RTSP ALG default port 554; "
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    dns:
        description:
        - "Field dns"
        required: False
        suboptions:
            default_port_disable:
                description:
                - "'default-port-disable'= Disable DNS ALG default port 53; "
            uuid:
                description:
                - "uuid of the object"
    tftp:
        description:
        - "Field tftp"
        required: False
        suboptions:
            default_port_disable:
                description:
                - "'default-port-disable'= Disable TFTP ALG default port 69; "
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    icmp:
        description:
        - "Field icmp"
        required: False
        suboptions:
            disable:
                description:
                - "'disable'= Disable ICMP ALG which allows ICMP errors to pass the firewall; "
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
AVAILABLE_PROPERTIES = ["dns","ftp","icmp","pptp","rtsp","sip","tftp","uuid",]

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
        ftp=dict(type='dict',default_port_disable=dict(type='str',choices=['default-port-disable']),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','client-port-request','client-eprt-request','server-pasv-reply','server-epsv-reply','port-retransmits','pasv-retransmits','smp-app-type-mismatch','retransmit-sanity-check-failure','smp-conn-alloc-failure','port-helper-created','pasv-helper-created','port-helper-acquire-in-del-q','port-helper-acquire-already-used','pasv-helper-acquire-in-del-q','pasv-helper-acquire-already-used','port-helper-freed-used','port-helper-freed-unused','pasv-helper-freed-used','pasv-helper-freed-unused'])),uuid=dict(type='str',)),
        sip=dict(type='dict',default_port_disable=dict(type='str',choices=['default-port-disable']),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','stat-request','stat-response','method-register','method-invite','method-ack','method-cancel','method-bye','method-options','method-prack','method-subscribe','method-notify','method-publish','method-info','method-refer','method-message','method-update','method-unknown','parse-error','keep-alive','contact-error','sdp-error','rtp-port-no-op','rtp-rtcp-port-success','rtp-port-failure','rtcp-port-failure','contact-port-no-op','contact-port-success','contact-port-failure','contact-new','contact-alloc-failure','contact-eim','contact-eim-set','rtp-new','rtp-alloc-failure','rtp-eim','helper-found','helper-created','helper-deleted','helper-freed','helper-failure'])),uuid=dict(type='str',)),
        uuid=dict(type='str',),
        pptp=dict(type='dict',default_port_disable=dict(type='str',choices=['default-port-disable']),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','calls-established','call-req-pns-call-id-mismatch','call-reply-pns-call-id-mismatch','gre-session-created','gre-session-freed','call-req-retransmit','call-req-new','call-req-ext-alloc-failure','call-reply-call-id-unknown','call-reply-retransmit','call-reply-ext-ext-alloc-failure','smp-app-type-mismatch','smp-client-call-id-mismatch','smp-sessions-created','smp-sessions-freed','smp-alloc-failure','gre-conn-creation-failure','gre-conn-ext-creation-failure','gre-no-fwd-route','gre-no-rev-route','gre-no-control-conn','gre-conn-already-exists','gre-free-no-ext','gre-free-no-smp','gre-free-smp-app-type-mismatch','control-freed','control-free-no-ext','control-free-no-smp','control-free-smp-app-type-mismatch'])),uuid=dict(type='str',)),
        rtsp=dict(type='dict',default_port_disable=dict(type='str',choices=['default-port-disable']),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','transport-inserted','transport-freed','transport-alloc-failure','data-session-created','data-session-freed','ext-creation-failure','transport-add-to-ext','transport-removed-from-ext','transport-too-many','transport-already-in-ext','transport-exists','transport-link-ext-failure-control','transport-link-ext-data','transport-link-ext-failure-data','transport-inserted-shadow','transport-creation-race','transport-alloc-failure-shadow','transport-put-in-del-q','transport-freed-shadow','transport-acquired-from-control','transport-found-from-prev-control','transport-acquire-failure-from-control','transport-released-from-control','transport-double-release-from-control','transport-acquired-from-data','transport-acquire-failure-from-data','transport-released-from-data','transport-double-release-from-data','transport-retry-lookup-on-data-free','transport-not-found-on-data-free','data-session-created-shadow','data-session-freed-shadow','ha-control-ext-creation-failure','ha-control-session-created','ha-data-session-created'])),uuid=dict(type='str',)),
        dns=dict(type='dict',default_port_disable=dict(type='str',choices=['default-port-disable']),uuid=dict(type='str',)),
        tftp=dict(type='dict',default_port_disable=dict(type='str',choices=['default-port-disable']),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','session-created','helper-created','helper-freed','helper-freed-used','helper-freed-unused','helper-already-used','helper-in-rml'])),uuid=dict(type='str',)),
        icmp=dict(type='dict',disable=dict(type='str',choices=['disable']),uuid=dict(type='str',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/alg"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/alg"

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
        for k, v in payload["alg"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["alg"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["alg"][k] = v
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
    payload = build_json("alg", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
        return result
    else:
        return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("alg", module)
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
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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