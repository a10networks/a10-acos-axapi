#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_sip
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - SIP Template Name
    
    alg-source-nat:
        description:
            - Translate source IP to NAT IP in SIP message when source NAT is used
    
    alg-dest-nat:
        description:
            - Translate VIP to real server IP in SIP message when destination NAT is used
    
    call-id-persist-disable:
        description:
            - Disable call-ID persistence
    
    client-keep-alive:
        description:
            - Respond client keep-alive packet directly instead of forwarding to server
    
    pstn-gw:
        description:
            - configure pstn gw host name for tel: uri translate to sip: uri (Hostname String, default is "pstn")
    
    client-request-header:
        
    
    client-response-header:
        
    
    exclude-translation:
        
    
    failed-client-selection:
        description:
            - Define action when select client fail
    
    drop-when-client-fail:
        description:
            - Drop current SIP message when select client fail
    
    failed-client-selection-message:
        description:
            - Send SIP message (includs status code) to server when select client fail(Format: 3 digits(1XX~6XX) space reason)
    
    failed-server-selection:
        description:
            - Define action when select server fail
    
    drop-when-server-fail:
        description:
            - Drop current SIP message when select server fail
    
    failed-server-selection-message:
        description:
            - Send SIP message (includs status code) to client when select server fail(Format: 3 digits(1XX~6XX) space reason)
    
    insert-client-ip:
        description:
            - Insert Client IP address into SIP header
    
    keep-server-ip-if-match-acl:
        description:
            - Use Real Server IP for addresses matching the ACL for a Call-Id
    
    acl-id:
        description:
            - ACL id
    
    acl-name-value:
        description:
            - IPv4 Access List Name
    
    service-group:
        description:
            - service group name
    
    server-keep-alive:
        description:
            - Send server keep-alive packet for every persist connection when enable conn-reuse
    
    interval:
        description:
            - The interval of keep-alive packet for each persist connection (second)
    
    server-request-header:
        
    
    server-response-header:
        
    
    smp-call-id-rtp-session:
        description:
            - Create the across cpu call-id rtp session
    
    server-selection-per-request:
        description:
            - Force server selection on every SIP request
    
    timeout:
        description:
            - Time in minutes
    
    dialog-aware:
        description:
            - Permit system processes dialog session
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"acl_id","acl_name_value","alg_dest_nat","alg_source_nat","call_id_persist_disable","client_keep_alive","client_request_header","client_response_header","dialog_aware","drop_when_client_fail","drop_when_server_fail","exclude_translation","failed_client_selection","failed_client_selection_message","failed_server_selection","failed_server_selection_message","insert_client_ip","interval","keep_server_ip_if_match_acl","name","pstn_gw","server_keep_alive","server_request_header","server_response_header","server_selection_per_request","service_group","smp_call_id_rtp_session","timeout","user_tag","uuid",}

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        
        acl_id=dict(
            type='str' 
        ),
        acl_name_value=dict(
            type='str' 
        ),
        alg_dest_nat=dict(
            type='str' 
        ),
        alg_source_nat=dict(
            type='str' 
        ),
        call_id_persist_disable=dict(
            type='str' 
        ),
        client_keep_alive=dict(
            type='str' 
        ),
        client_request_header=dict(
            type='str' 
        ),
        client_response_header=dict(
            type='str' 
        ),
        dialog_aware=dict(
            type='str' 
        ),
        drop_when_client_fail=dict(
            type='str' 
        ),
        drop_when_server_fail=dict(
            type='str' 
        ),
        exclude_translation=dict(
            type='str' 
        ),
        failed_client_selection=dict(
            type='str' 
        ),
        failed_client_selection_message=dict(
            type='str' 
        ),
        failed_server_selection=dict(
            type='str' 
        ),
        failed_server_selection_message=dict(
            type='str' 
        ),
        insert_client_ip=dict(
            type='str' 
        ),
        interval=dict(
            type='str' 
        ),
        keep_server_ip_if_match_acl=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        pstn_gw=dict(
            type='str' 
        ),
        server_keep_alive=dict(
            type='str' 
        ),
        server_request_header=dict(
            type='str' 
        ),
        server_response_header=dict(
            type='str' 
        ),
        server_selection_per_request=dict(
            type='str' 
        ),
        service_group=dict(
            type='str' 
        ),
        smp_call_id_rtp_session=dict(
            type='str' 
        ),
        timeout=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/sip/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/sip/{name}"
    f_dict = {}
    
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
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

def update(module, result):
    payload = build_json("sip", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

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
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid, validation_errors = validate(module.params)
    map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
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