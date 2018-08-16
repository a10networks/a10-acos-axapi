#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_fw_template_logging
description:
    - None
short_description: Configures A10 fw.template.logging
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
    include_http:
        description:
        - "Field include_http"
        required: False
        suboptions:
            header_cfg:
                description:
                - "Field header_cfg"
            request_number:
                description:
                - "None"
            file_extension:
                description:
                - "None"
            method:
                description:
                - "None"
            l4_session_info:
                description:
                - "None"
    severity:
        description:
        - "None"
        required: False
    source_address:
        description:
        - "Field source_address"
        required: False
        suboptions:
            ip:
                description:
                - "None"
            uuid:
                description:
                - "None"
            ipv6:
                description:
                - "None"
    format:
        description:
        - "None"
        required: False
    log:
        description:
        - "Field log"
        required: False
        suboptions:
            http_requests:
                description:
                - "None"
    facility:
        description:
        - "None"
        required: False
    include_radius_attribute:
        description:
        - "Field include_radius_attribute"
        required: False
        suboptions:
            framed_ipv6_prefix:
                description:
                - "None"
            prefix_length:
                description:
                - "None"
            insert_if_not_existing:
                description:
                - "None"
            zero_in_custom_attr:
                description:
                - "None"
            no_quote:
                description:
                - "None"
            attr_cfg:
                description:
                - "Field attr_cfg"
    uuid:
        description:
        - "None"
        required: False
    rule:
        description:
        - "Field rule"
        required: False
        suboptions:
            rule_http_requests:
                description:
                - "Field rule_http_requests"
    service_group:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    resolution:
        description:
        - "None"
        required: False
    name:
        description:
        - "None"
        required: True


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["facility","format","include_http","include_radius_attribute","log","name","resolution","rule","service_group","severity","source_address","user_tag","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        include_http=dict(type='dict',header_cfg=dict(type='list',custom_max_length=dict(type='int',),http_header=dict(type='str',choices=['cookie','referer','user-agent','header1','header2','header3']),max_length=dict(type='int',),custom_header_name=dict(type='str',)),request_number=dict(type='bool',),file_extension=dict(type='bool',),method=dict(type='bool',),l4_session_info=dict(type='bool',)),
        severity=dict(type='str',choices=['emergency','alert','critical','error','warning','notice','informational','debug']),
        source_address=dict(type='dict',ip=dict(type='str',),uuid=dict(type='str',),ipv6=dict(type='str',)),
        format=dict(type='str',choices=['ascii','cef']),
        log=dict(type='dict',http_requests=dict(type='str',choices=['host','url'])),
        facility=dict(type='str',choices=['kernel','user','mail','daemon','security-authorization','syslog','line-printer','news','uucp','cron','security-authorization-private','ftp','ntp','audit','alert','clock','local0','local1','local2','local3','local4','local5','local6','local7']),
        include_radius_attribute=dict(type='dict',framed_ipv6_prefix=dict(type='bool',),prefix_length=dict(type='str',choices=['32','48','64','80','96','112']),insert_if_not_existing=dict(type='bool',),zero_in_custom_attr=dict(type='bool',),no_quote=dict(type='bool',),attr_cfg=dict(type='list',attr_event=dict(type='str',choices=['http-requests','sessions']),attr=dict(type='str',choices=['imei','imsi','msisdn','custom1','custom2','custom3']))),
        uuid=dict(type='str',),
        rule=dict(type='dict',rule_http_requests=dict(type='dict',log_every_http_request=dict(type='bool',),disable_sequence_check=dict(type='bool',),include_all_headers=dict(type='bool',),dest_port=dict(type='list',include_byte_count=dict(type='bool',),dest_port_number=dict(type='int',)),max_url_len=dict(type='int',))),
        service_group=dict(type='str',),
        user_tag=dict(type='str',),
        resolution=dict(type='str',choices=['seconds','10-milliseconds']),
        name=dict(type='str',required=True,)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/template/logging/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/template/logging/{name}"
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

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("logging", module)
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
    payload = build_json("logging", module)
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