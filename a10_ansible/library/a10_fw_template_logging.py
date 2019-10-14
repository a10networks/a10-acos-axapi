#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_fw_template_logging
description:
    - Logging Template
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
                - "HTTP Request Number"
            file_extension:
                description:
                - "HTTP file extension"
            method:
                description:
                - "Log the HTTP Request Method"
            l4_session_info:
                description:
                - "Log the L4 session information of the HTTP request"
    merged_style:
        description:
        - "Merge creation and deletion of session logs to one"
        required: False
    name:
        description:
        - "Logging Template Name"
        required: True
    source_address:
        description:
        - "Field source_address"
        required: False
        suboptions:
            ip:
                description:
                - "Specify source IP address"
            uuid:
                description:
                - "uuid of the object"
            ipv6:
                description:
                - "Specify source IPv6 address"
    format:
        description:
        - "'ascii'= A10 Text logging format (ASCII); 'cef'= Common Event Format for logging (default); "
        required: False
    log:
        description:
        - "Field log"
        required: False
        suboptions:
            http_requests:
                description:
                - "'host'= Log the HTTP Host Header; 'url'= Log the HTTP Request URL; "
    severity:
        description:
        - "'emergency'= 0= Emergency; 'alert'= 1= Alert; 'critical'= 2= Critical; 'error'= 3= Error; 'warning'= 4= Warning; 'notice'= 5= Notice; 'informational'= 6= Informational; 'debug'= 7= Debug; "
        required: False
    include_dest_fqdn:
        description:
        - "Include destination FQDN string"
        required: False
    facility:
        description:
        - "'kernel'= 0= Kernel; 'user'= 1= User-level; 'mail'= 2= Mail; 'daemon'= 3= System daemons; 'security-authorization'= 4= Security/authorization; 'syslog'= 5= Syslog internal; 'line-printer'= 6= Line printer; 'news'= 7= Network news; 'uucp'= 8= UUCP subsystem; 'cron'= 9= Time-related; 'security-authorization-private'= 10= Private security/authorization; 'ftp'= 11= FTP; 'ntp'= 12= NTP; 'audit'= 13= Audit; 'alert'= 14= Alert; 'clock'= 15= Clock-related; 'local0'= 16= Local use 0; 'local1'= 17= Local use 1; 'local2'= 18= Local use 2; 'local3'= 19= Local use 3; 'local4'= 20= Local use 4; 'local5'= 21= Local use 5; 'local6'= 22= Local use 6; 'local7'= 23= Local use 7; "
        required: False
    include_radius_attribute:
        description:
        - "Field include_radius_attribute"
        required: False
        suboptions:
            framed_ipv6_prefix:
                description:
                - "Include radius attributes for the prefix"
            prefix_length:
                description:
                - "'32'= Prefix length 32; '48'= Prefix length 48; '64'= Prefix length 64; '80'= Prefix length 80; '96'= Prefix length 96; '112'= Prefix length 112; "
            insert_if_not_existing:
                description:
                - "Configure what string is to be inserted for custom RADIUS attributes"
            zero_in_custom_attr:
                description:
                - "Insert 0000 for standard and custom attributes in log string"
            no_quote:
                description:
                - "No quotation marks for RADIUS attributes in logs"
            attr_cfg:
                description:
                - "Field attr_cfg"
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
        - "Bind a Service Group to the logging template (Service Group Name)"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    resolution:
        description:
        - "'seconds'= Logging timestamp resolution in seconds (default); '10-milliseconds'= Logging timestamp resolution in 10s of milli-seconds; "
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
AVAILABLE_PROPERTIES = ["facility","format","include_dest_fqdn","include_http","include_radius_attribute","log","merged_style","name","resolution","rule","service_group","severity","source_address","user_tag","uuid",]

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
        include_http=dict(type='dict',header_cfg=dict(type='list',custom_max_length=dict(type='int',),http_header=dict(type='str',choices=['cookie','referer','user-agent','header1','header2','header3']),max_length=dict(type='int',),custom_header_name=dict(type='str',)),request_number=dict(type='bool',),file_extension=dict(type='bool',),method=dict(type='bool',),l4_session_info=dict(type='bool',)),
        merged_style=dict(type='bool',),
        name=dict(type='str',required=True,),
        source_address=dict(type='dict',ip=dict(type='str',),uuid=dict(type='str',),ipv6=dict(type='str',)),
        format=dict(type='str',choices=['ascii','cef']),
        log=dict(type='dict',http_requests=dict(type='str',choices=['host','url'])),
        severity=dict(type='str',choices=['emergency','alert','critical','error','warning','notice','informational','debug']),
        include_dest_fqdn=dict(type='bool',),
        facility=dict(type='str',choices=['kernel','user','mail','daemon','security-authorization','syslog','line-printer','news','uucp','cron','security-authorization-private','ftp','ntp','audit','alert','clock','local0','local1','local2','local3','local4','local5','local6','local7']),
        include_radius_attribute=dict(type='dict',framed_ipv6_prefix=dict(type='bool',),prefix_length=dict(type='str',choices=['32','48','64','80','96','112']),insert_if_not_existing=dict(type='bool',),zero_in_custom_attr=dict(type='bool',),no_quote=dict(type='bool',),attr_cfg=dict(type='list',attr_event=dict(type='str',choices=['http-requests','sessions']),attr=dict(type='str',choices=['imei','imsi','msisdn','custom1','custom2','custom3']))),
        rule=dict(type='dict',rule_http_requests=dict(type='dict',log_every_http_request=dict(type='bool',),disable_sequence_check=dict(type='bool',),include_all_headers=dict(type='bool',),dest_port=dict(type='list',include_byte_count=dict(type='bool',),dest_port_number=dict(type='int',)),max_url_len=dict(type='int',))),
        service_group=dict(type='str',),
        user_tag=dict(type='str',),
        resolution=dict(type='str',choices=['seconds','10-milliseconds']),
        uuid=dict(type='str',)
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

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

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

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
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

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
        return result
    else:
        return delete(module, result)

def replace(module, result, existing_config, payload):
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