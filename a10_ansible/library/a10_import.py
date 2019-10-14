#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_import
description:
    - Get files from remote site
short_description: Configures A10 import
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
    geo_location:
        description:
        - "Geo-location CSV File"
        required: False
    ssl_cert_key:
        description:
        - "'bulk'= import an archive file; "
        required: False
    class_list_convert:
        description:
        - "Convert Class List File to A10 format"
        required: False
    bw_list:
        description:
        - "Black white List File"
        required: False
    usb_license:
        description:
        - "USB License File"
        required: False
    ip_map_list:
        description:
        - "IP Map List File"
        required: False
    health_external:
        description:
        - "Field health_external"
        required: False
        suboptions:
            description:
                description:
                - "Describe the Program Function briefly"
            remote_file:
                description:
                - "Field remote_file"
            externalfilename:
                description:
                - "Specify the Program Name"
            password:
                description:
                - "password for the remote site"
            use_mgmt_port:
                description:
                - "Use management port as source port"
            overwrite:
                description:
                - "Overwrite existing file"
    auth_portal:
        description:
        - "Portal file for http authentication"
        required: False
    local_uri_file:
        description:
        - "Local URI files for http response"
        required: False
    aflex:
        description:
        - "aFleX Script Source File"
        required: False
    overwrite:
        description:
        - "Overwrite existing file"
        required: False
    class_list_type:
        description:
        - "'ac'= ac; 'ipv4'= ipv4; 'ipv6'= ipv6; 'string'= string; 'string-case-insensitive'= string-case-insensitive; "
        required: False
    pfx_password:
        description:
        - "The password for certificate file (pfx type only)"
        required: False
    web_category_license:
        description:
        - "License file to enable web-category feature"
        required: False
    thales_kmdata:
        description:
        - "Thales Kmdata files"
        required: False
    secured:
        description:
        - "Mark as non-exportable"
        required: False
    ssl_crl:
        description:
        - "SSL Crl File"
        required: False
    terminal:
        description:
        - "terminal vi"
        required: False
    policy:
        description:
        - "WAF policy File"
        required: False
    file_inspection_bw_list:
        description:
        - "Black white List File"
        required: False
    thales_secworld:
        description:
        - "Thales security world files"
        required: False
    lw_4o6:
        description:
        - "LW-4over6 Binding Table File"
        required: False
    auth_portal_image:
        description:
        - "Image file for default portal"
        required: False
    health_postfile:
        description:
        - "Field health_postfile"
        required: False
        suboptions:
            postfilename:
                description:
                - "Specify the File Name"
            password:
                description:
                - "password for the remote site"
            use_mgmt_port:
                description:
                - "Use management port as source port"
            remote_file:
                description:
                - "Profile name for remote url"
            overwrite:
                description:
                - "Overwrite existing file"
    class_list:
        description:
        - "Class List File"
        required: False
    glm_license:
        description:
        - "License File"
        required: False
    dnssec_ds:
        description:
        - "DNSSEC DS file for child zone"
        required: False
    cloud_creds:
        description:
        - "Cloud Credentials File"
        required: False
    auth_jwks:
        description:
        - "JSON web key"
        required: False
    wsdl:
        description:
        - "Web Service Definition Language File"
        required: False
    password:
        description:
        - "password for the remote site"
        required: False
    ssl_key:
        description:
        - "SSL Key File(enter bulk when import an archive file)"
        required: False
    use_mgmt_port:
        description:
        - "Use management port as source port"
        required: False
    remote_file:
        description:
        - "profile name for remote url"
        required: False
    cloud_config:
        description:
        - "Cloud Configuration File"
        required: False
    to_device:
        description:
        - "Field to_device"
        required: False
        suboptions:
            web_category_license:
                description:
                - "License file to enable web-category feature"
            remote_file:
                description:
                - "profile name for remote url"
            glm_license:
                description:
                - "License File"
            glm_cert:
                description:
                - "GLM certificate"
            device:
                description:
                - "Device (Device ID)"
            use_mgmt_port:
                description:
                - "Use management port as source port"
            overwrite:
                description:
                - "Overwrite existing file"
    user_tag:
        description:
        - "Customized tag"
        required: False
    store_name:
        description:
        - "Import store name"
        required: False
    ca_cert:
        description:
        - "CA Cert File(enter bulk when import an archive file)"
        required: False
    glm_cert:
        description:
        - "GLM certificate"
        required: False
    store:
        description:
        - "Field store"
        required: False
        suboptions:
            create:
                description:
                - "Create an import store profile"
            name:
                description:
                - "profile name to store remote url"
            remote_file:
                description:
                - "Field remote_file"
            delete:
                description:
                - "Delete an import store profile"
    xml_schema:
        description:
        - "XML-Schema File"
        required: False
    certificate_type:
        description:
        - "'pem'= pem; 'der'= der; 'pfx'= pfx; 'p7b'= p7b; "
        required: False
    auth_saml_idp:
        description:
        - "Field auth_saml_idp"
        required: False
        suboptions:
            remote_file:
                description:
                - "Profile name for remote url"
            saml_idp_name:
                description:
                - "Metadata name"
            verify_xml_signature:
                description:
                - "Verify metadata's XML signature"
            password:
                description:
                - "password for the remote site"
            use_mgmt_port:
                description:
                - "Use management port as source port"
            overwrite:
                description:
                - "Overwrite existing file"
    ssl_cert:
        description:
        - "SSL Cert File(enter bulk when import an archive file)"
        required: False
    dnssec_dnskey:
        description:
        - "DNSSEC DNSKEY(KSK) file for child zone"
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
AVAILABLE_PROPERTIES = ["aflex","auth_jwks","auth_portal","auth_portal_image","auth_saml_idp","bw_list","ca_cert","certificate_type","class_list","class_list_convert","class_list_type","cloud_config","cloud_creds","dnssec_dnskey","dnssec_ds","file_inspection_bw_list","geo_location","glm_cert","glm_license","health_external","health_postfile","ip_map_list","local_uri_file","lw_4o6","overwrite","password","pfx_password","policy","remote_file","secured","ssl_cert","ssl_cert_key","ssl_crl","ssl_key","store","store_name","terminal","thales_kmdata","thales_secworld","to_device","usb_license","use_mgmt_port","user_tag","web_category_license","wsdl","xml_schema",]

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
        geo_location=dict(type='str',),
        ssl_cert_key=dict(type='str',choices=['bulk']),
        class_list_convert=dict(type='str',),
        bw_list=dict(type='str',),
        usb_license=dict(type='str',),
        ip_map_list=dict(type='str',),
        health_external=dict(type='dict',description=dict(type='str',),remote_file=dict(type='str',),externalfilename=dict(type='str',),password=dict(type='str',),use_mgmt_port=dict(type='bool',),overwrite=dict(type='bool',)),
        auth_portal=dict(type='str',),
        local_uri_file=dict(type='str',),
        aflex=dict(type='str',),
        overwrite=dict(type='bool',),
        class_list_type=dict(type='str',choices=['ac','ipv4','ipv6','string','string-case-insensitive']),
        pfx_password=dict(type='str',),
        web_category_license=dict(type='str',),
        thales_kmdata=dict(type='str',),
        secured=dict(type='bool',),
        ssl_crl=dict(type='str',),
        terminal=dict(type='bool',),
        policy=dict(type='str',),
        file_inspection_bw_list=dict(type='str',),
        thales_secworld=dict(type='str',),
        lw_4o6=dict(type='str',),
        auth_portal_image=dict(type='str',),
        health_postfile=dict(type='dict',postfilename=dict(type='str',),password=dict(type='str',),use_mgmt_port=dict(type='bool',),remote_file=dict(type='str',),overwrite=dict(type='bool',)),
        class_list=dict(type='str',),
        glm_license=dict(type='str',),
        dnssec_ds=dict(type='str',),
        cloud_creds=dict(type='str',),
        auth_jwks=dict(type='str',),
        wsdl=dict(type='str',),
        password=dict(type='str',),
        ssl_key=dict(type='str',),
        use_mgmt_port=dict(type='bool',),
        remote_file=dict(type='str',),
        cloud_config=dict(type='str',),
        to_device=dict(type='dict',web_category_license=dict(type='str',),remote_file=dict(type='str',),glm_license=dict(type='str',),glm_cert=dict(type='str',),device=dict(type='int',),use_mgmt_port=dict(type='bool',),overwrite=dict(type='bool',)),
        user_tag=dict(type='str',),
        store_name=dict(type='str',),
        ca_cert=dict(type='str',),
        glm_cert=dict(type='str',),
        store=dict(type='dict',create=dict(type='bool',),name=dict(type='str',),remote_file=dict(type='str',),delete=dict(type='bool',)),
        xml_schema=dict(type='str',),
        certificate_type=dict(type='str',choices=['pem','der','pfx','p7b']),
        auth_saml_idp=dict(type='dict',remote_file=dict(type='str',),saml_idp_name=dict(type='str',),verify_xml_signature=dict(type='bool',),password=dict(type='str',),use_mgmt_port=dict(type='bool',),overwrite=dict(type='bool',)),
        ssl_cert=dict(type='str',),
        dnssec_dnskey=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/import"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/import"

    f_dict = {}

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
        for k, v in payload["import"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["import"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["import"][k] = v
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
    payload = build_json("import", module)
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