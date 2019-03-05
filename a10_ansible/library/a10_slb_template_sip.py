#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_sip
description:
    - SIP Template
short_description: Configures A10 slb.template.sip
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

    server_request_header:
        description:
        - "Field server_request_header"
        required: False
        suboptions:
            server_request_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name= value'))"
            server_request_erase_all:
                description:
                - "Erase all headers"
            insert_condition_server_request:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-always'= Always insert the header even when there is a header with the same name; "
            server_request_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
    smp_call_id_rtp_session:
        description:
        - "Create the across cpu call-id rtp session"
        required: False
    keep_server_ip_if_match_acl:
        description:
        - "Use Real Server IP for addresses matching the ACL for a Call-Id"
        required: False
    client_keep_alive:
        description:
        - "Respond client keep-alive packet directly instead of forwarding to server"
        required: False
    alg_source_nat:
        description:
        - "Translate source IP to NAT IP in SIP message when source NAT is used"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    server_response_header:
        description:
        - "Field server_response_header"
        required: False
        suboptions:
            server_response_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name= value'))"
            insert_condition_server_response:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-always'= Always insert the header even when there is a header with the same name; "
            server_response_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
            server_response_erase_all:
                description:
                - "Erase all headers"
    server_selection_per_request:
        description:
        - "Force server selection on every SIP request"
        required: False
    client_request_header:
        description:
        - "Field client_request_header"
        required: False
        suboptions:
            client_request_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
            client_request_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name= value'))"
            client_request_erase_all:
                description:
                - "Erase all headers"
            insert_condition_client_request:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-always'= Always insert the header even when there is a header with the same name; "
    pstn_gw:
        description:
        - "configure pstn gw host name for tel= uri translate to sip= uri (Hostname String, default is 'pstn')"
        required: False
    service_group:
        description:
        - "service group name"
        required: False
    insert_client_ip:
        description:
        - "Insert Client IP address into SIP header"
        required: False
    failed_client_selection:
        description:
        - "Define action when select client fail"
        required: False
    failed_client_selection_message:
        description:
        - "Send SIP message (includs status code) to server when select client fail(Format= 3 digits(1XX~6XX) space reason)"
        required: False
    call_id_persist_disable:
        description:
        - "Disable call-ID persistence"
        required: False
    acl_id:
        description:
        - "ACL id"
        required: False
    alg_dest_nat:
        description:
        - "Translate VIP to real server IP in SIP message when destination NAT is used"
        required: False
    server_keep_alive:
        description:
        - "Send server keep-alive packet for every persist connection when enable conn-reuse"
        required: False
    client_response_header:
        description:
        - "Field client_response_header"
        required: False
        suboptions:
            client_response_erase_all:
                description:
                - "Erase all headers"
            insert_condition_client_response:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-always'= Always insert the header even when there is a header with the same name; "
            client_response_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
            client_response_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name= value'))"
    failed_server_selection_message:
        description:
        - "Send SIP message (includs status code) to client when select server fail(Format= 3 digits(1XX~6XX) space reason)"
        required: False
    name:
        description:
        - "SIP Template Name"
        required: True
    exclude_translation:
        description:
        - "Field exclude_translation"
        required: False
        suboptions:
            translation_value:
                description:
                - "'start-line'= SIP request line or status line; 'header'= SIP message headers; 'body'= SIP message body; "
            header_string:
                description:
                - "SIP header name"
    interval:
        description:
        - "The interval of keep-alive packet for each persist connection (second)"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    dialog_aware:
        description:
        - "Permit system processes dialog session"
        required: False
    failed_server_selection:
        description:
        - "Define action when select server fail"
        required: False
    drop_when_client_fail:
        description:
        - "Drop current SIP message when select client fail"
        required: False
    timeout:
        description:
        - "Time in minutes"
        required: False
    drop_when_server_fail:
        description:
        - "Drop current SIP message when select server fail"
        required: False
    acl_name_value:
        description:
        - "IPv4 Access List Name"
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
AVAILABLE_PROPERTIES = ["acl_id","acl_name_value","alg_dest_nat","alg_source_nat","call_id_persist_disable","client_keep_alive","client_request_header","client_response_header","dialog_aware","drop_when_client_fail","drop_when_server_fail","exclude_translation","failed_client_selection","failed_client_selection_message","failed_server_selection","failed_server_selection_message","insert_client_ip","interval","keep_server_ip_if_match_acl","name","pstn_gw","server_keep_alive","server_request_header","server_response_header","server_selection_per_request","service_group","smp_call_id_rtp_session","timeout","user_tag","uuid",]

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
        server_request_header=dict(type='list',server_request_header_insert=dict(type='str',),server_request_erase_all=dict(type='bool',),insert_condition_server_request=dict(type='str',choices=['insert-if-not-exist','insert-always']),server_request_header_erase=dict(type='str',)),
        smp_call_id_rtp_session=dict(type='bool',),
        keep_server_ip_if_match_acl=dict(type='bool',),
        client_keep_alive=dict(type='bool',),
        alg_source_nat=dict(type='bool',),
        uuid=dict(type='str',),
        server_response_header=dict(type='list',server_response_header_insert=dict(type='str',),insert_condition_server_response=dict(type='str',choices=['insert-if-not-exist','insert-always']),server_response_header_erase=dict(type='str',),server_response_erase_all=dict(type='bool',)),
        server_selection_per_request=dict(type='bool',),
        client_request_header=dict(type='list',client_request_header_erase=dict(type='str',),client_request_header_insert=dict(type='str',),client_request_erase_all=dict(type='bool',),insert_condition_client_request=dict(type='str',choices=['insert-if-not-exist','insert-always'])),
        pstn_gw=dict(type='str',),
        service_group=dict(type='str',),
        insert_client_ip=dict(type='bool',),
        failed_client_selection=dict(type='bool',),
        failed_client_selection_message=dict(type='str',),
        call_id_persist_disable=dict(type='bool',),
        acl_id=dict(type='int',),
        alg_dest_nat=dict(type='bool',),
        server_keep_alive=dict(type='bool',),
        client_response_header=dict(type='list',client_response_erase_all=dict(type='bool',),insert_condition_client_response=dict(type='str',choices=['insert-if-not-exist','insert-always']),client_response_header_erase=dict(type='str',),client_response_header_insert=dict(type='str',)),
        failed_server_selection_message=dict(type='str',),
        name=dict(type='str',required=True,),
        exclude_translation=dict(type='list',translation_value=dict(type='str',choices=['start-line','header','body']),header_string=dict(type='str',)),
        interval=dict(type='int',),
        user_tag=dict(type='str',),
        dialog_aware=dict(type='bool',),
        failed_server_selection=dict(type='bool',),
        drop_when_client_fail=dict(type='bool',),
        timeout=dict(type='int',),
        drop_when_server_fail=dict(type='bool',),
        acl_name_value=dict(type='str',)
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
    payload = build_json("sip", module)
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
    payload = build_json("sip", module)
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