#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_sip
description:
    - None
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
    name:
        description:
        - "None"
        required: True
    alg_source_nat:
        description:
        - "None"
        required: False
    alg_dest_nat:
        description:
        - "None"
        required: False
    call_id_persist_disable:
        description:
        - "None"
        required: False
    client_keep_alive:
        description:
        - "None"
        required: False
    pstn_gw:
        description:
        - "None"
        required: False
    client_request_header:
        description:
        - "Field client_request_header"
        required: False
        suboptions:
            client_request_header_erase:
                description:
                - "None"
            client_request_erase_all:
                description:
                - "None"
            client_request_header_insert:
                description:
                - "None"
            insert_condition_client_request:
                description:
                - "None"
    client_response_header:
        description:
        - "Field client_response_header"
        required: False
        suboptions:
            client_response_header_erase:
                description:
                - "None"
            client_response_erase_all:
                description:
                - "None"
            client_response_header_insert:
                description:
                - "None"
            insert_condition_client_response:
                description:
                - "None"
    exclude_translation:
        description:
        - "Field exclude_translation"
        required: False
        suboptions:
            translation_value:
                description:
                - "None"
            header_string:
                description:
                - "None"
    failed_client_selection:
        description:
        - "None"
        required: False
    drop_when_client_fail:
        description:
        - "None"
        required: False
    failed_client_selection_message:
        description:
        - "None"
        required: False
    failed_server_selection:
        description:
        - "None"
        required: False
    drop_when_server_fail:
        description:
        - "None"
        required: False
    failed_server_selection_message:
        description:
        - "None"
        required: False
    insert_client_ip:
        description:
        - "None"
        required: False
    keep_server_ip_if_match_acl:
        description:
        - "None"
        required: False
    acl_id:
        description:
        - "None"
        required: False
    acl_name_value:
        description:
        - "None"
        required: False
    service_group:
        description:
        - "None"
        required: False
    server_keep_alive:
        description:
        - "None"
        required: False
    interval:
        description:
        - "None"
        required: False
    server_request_header:
        description:
        - "Field server_request_header"
        required: False
        suboptions:
            server_request_header_erase:
                description:
                - "None"
            server_request_erase_all:
                description:
                - "None"
            server_request_header_insert:
                description:
                - "None"
            insert_condition_server_request:
                description:
                - "None"
    server_response_header:
        description:
        - "Field server_response_header"
        required: False
        suboptions:
            server_response_header_erase:
                description:
                - "None"
            server_response_erase_all:
                description:
                - "None"
            server_response_header_insert:
                description:
                - "None"
            insert_condition_server_response:
                description:
                - "None"
    smp_call_id_rtp_session:
        description:
        - "None"
        required: False
    server_selection_per_request:
        description:
        - "None"
        required: False
    timeout:
        description:
        - "None"
        required: False
    dialog_aware:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
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
    from a10_ansible.axapi_http import client_factory
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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        name=dict(type='str',required=True,),
        alg_source_nat=dict(type='bool',),
        alg_dest_nat=dict(type='bool',),
        call_id_persist_disable=dict(type='bool',),
        client_keep_alive=dict(type='bool',),
        pstn_gw=dict(type='str',),
        client_request_header=dict(type='list',client_request_header_erase=dict(type='str',),client_request_erase_all=dict(type='bool',),client_request_header_insert=dict(type='str',),insert_condition_client_request=dict(type='str',choices=['insert-if-not-exist','insert-always'])),
        client_response_header=dict(type='list',client_response_header_erase=dict(type='str',),client_response_erase_all=dict(type='bool',),client_response_header_insert=dict(type='str',),insert_condition_client_response=dict(type='str',choices=['insert-if-not-exist','insert-always'])),
        exclude_translation=dict(type='list',translation_value=dict(type='str',choices=['start-line','header','body']),header_string=dict(type='str',)),
        failed_client_selection=dict(type='bool',),
        drop_when_client_fail=dict(type='bool',),
        failed_client_selection_message=dict(type='str',),
        failed_server_selection=dict(type='bool',),
        drop_when_server_fail=dict(type='bool',),
        failed_server_selection_message=dict(type='str',),
        insert_client_ip=dict(type='bool',),
        keep_server_ip_if_match_acl=dict(type='bool',),
        acl_id=dict(type='int',),
        acl_name_value=dict(type='str',),
        service_group=dict(type='str',),
        server_keep_alive=dict(type='bool',),
        interval=dict(type='int',),
        server_request_header=dict(type='list',server_request_header_erase=dict(type='str',),server_request_erase_all=dict(type='bool',),server_request_header_insert=dict(type='str',),insert_condition_server_request=dict(type='str',choices=['insert-if-not-exist','insert-always'])),
        server_response_header=dict(type='list',server_response_header_erase=dict(type='str',),server_response_erase_all=dict(type='bool',),server_response_header_insert=dict(type='str',),insert_condition_server_response=dict(type='str',choices=['insert-if-not-exist','insert-always'])),
        smp_call_id_rtp_session=dict(type='bool',),
        server_selection_per_request=dict(type='bool',),
        timeout=dict(type='int',),
        dialog_aware=dict(type='bool',),
        uuid=dict(type='str',),
        user_tag=dict(type='str',)
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

    valid = True

    if state == 'present':
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