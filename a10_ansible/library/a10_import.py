#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_import
description:
    - None
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
    geo_location:
        description:
        - "None"
        required: False
    ssl_cert_key:
        description:
        - "None"
        required: False
    class_list_convert:
        description:
        - "None"
        required: False
    bw_list:
        description:
        - "None"
        required: False
    usb_license:
        description:
        - "None"
        required: False
    health_external:
        description:
        - "Field health_external"
        required: False
        suboptions:
            description:
                description:
                - "None"
            remote_file:
                description:
                - "Field remote_file"
            externalfilename:
                description:
                - "None"
            password:
                description:
                - "None"
            use_mgmt_port:
                description:
                - "None"
            overwrite:
                description:
                - "None"
    auth_portal:
        description:
        - "None"
        required: False
    aflex:
        description:
        - "None"
        required: False
    overwrite:
        description:
        - "None"
        required: False
    class_list_type:
        description:
        - "None"
        required: False
    pfx_password:
        description:
        - "None"
        required: False
    web_category_license:
        description:
        - "None"
        required: False
    thales_kmdata:
        description:
        - "None"
        required: False
    ssl_crl:
        description:
        - "None"
        required: False
    terminal:
        description:
        - "None"
        required: False
    policy:
        description:
        - "None"
        required: False
    file_inspection_bw_list:
        description:
        - "None"
        required: False
    thales_secworld:
        description:
        - "None"
        required: False
    lw_4o6:
        description:
        - "None"
        required: False
    auth_portal_image:
        description:
        - "None"
        required: False
    health_postfile:
        description:
        - "Field health_postfile"
        required: False
        suboptions:
            postfilename:
                description:
                - "None"
            password:
                description:
                - "None"
            use_mgmt_port:
                description:
                - "None"
            remote_file:
                description:
                - "None"
            overwrite:
                description:
                - "None"
    class_list:
        description:
        - "None"
        required: False
    glm_license:
        description:
        - "None"
        required: False
    dnssec_ds:
        description:
        - "None"
        required: False
    local_uri_file:
        description:
        - "None"
        required: False
    wsdl:
        description:
        - "None"
        required: False
    password:
        description:
        - "None"
        required: False
    file_inspection_use_mgmt_port:
        description:
        - "None"
        required: False
    ssl_key:
        description:
        - "None"
        required: False
    use_mgmt_port:
        description:
        - "None"
        required: False
    remote_file:
        description:
        - "None"
        required: False
    to_device:
        description:
        - "Field to_device"
        required: False
        suboptions:
            web_category_license:
                description:
                - "None"
            remote_file:
                description:
                - "None"
            glm_license:
                description:
                - "None"
            glm_cert:
                description:
                - "None"
            device:
                description:
                - "None"
            use_mgmt_port:
                description:
                - "None"
            overwrite:
                description:
                - "None"
    user_tag:
        description:
        - "None"
        required: False
    store_name:
        description:
        - "None"
        required: False
    ca_cert:
        description:
        - "None"
        required: False
    glm_cert:
        description:
        - "None"
        required: False
    store:
        description:
        - "Field store"
        required: False
        suboptions:
            create:
                description:
                - "None"
            name:
                description:
                - "None"
            remote_file:
                description:
                - "Field remote_file"
            delete:
                description:
                - "None"
    xml_schema:
        description:
        - "None"
        required: False
    certificate_type:
        description:
        - "None"
        required: False
    auth_saml_idp:
        description:
        - "Field auth_saml_idp"
        required: False
        suboptions:
            remote_file:
                description:
                - "None"
            saml_idp_name:
                description:
                - "None"
            verify_xml_signature:
                description:
                - "None"
            password:
                description:
                - "None"
            use_mgmt_port:
                description:
                - "None"
            overwrite:
                description:
                - "None"
    ssl_cert:
        description:
        - "None"
        required: False
    dnssec_dnskey:
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
AVAILABLE_PROPERTIES = ["aflex","auth_portal","auth_portal_image","auth_saml_idp","bw_list","ca_cert","certificate_type","class_list","class_list_convert","class_list_type","dnssec_dnskey","dnssec_ds","file_inspection_bw_list","file_inspection_use_mgmt_port","geo_location","glm_cert","glm_license","health_external","health_postfile","local_uri_file","lw_4o6","overwrite","password","pfx_password","policy","remote_file","ssl_cert","ssl_cert_key","ssl_crl","ssl_key","store","store_name","terminal","thales_kmdata","thales_secworld","to_device","usb_license","use_mgmt_port","user_tag","web_category_license","wsdl","xml_schema",]

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
        geo_location=dict(type='str',),
        ssl_cert_key=dict(type='str',choices=['bulk']),
        class_list_convert=dict(type='str',),
        bw_list=dict(type='str',),
        usb_license=dict(type='str',),
        health_external=dict(type='dict',description=dict(type='str',),remote_file=dict(type='str',),externalfilename=dict(type='str',),password=dict(type='str',),use_mgmt_port=dict(type='bool',),overwrite=dict(type='bool',)),
        auth_portal=dict(type='str',),
        aflex=dict(type='str',),
        overwrite=dict(type='bool',),
        class_list_type=dict(type='str',choices=['ac','ipv4','ipv6','string','string-case-insensitive']),
        pfx_password=dict(type='str',),
        web_category_license=dict(type='str',),
        thales_kmdata=dict(type='str',),
        ssl_crl=dict(type='str',),
        terminal=dict(type='bool',),
        policy=dict(type='str',),
        file_inspection_bw_list=dict(type='bool',),
        thales_secworld=dict(type='str',),
        lw_4o6=dict(type='str',),
        auth_portal_image=dict(type='str',),
        health_postfile=dict(type='dict',postfilename=dict(type='str',),password=dict(type='str',),use_mgmt_port=dict(type='bool',),remote_file=dict(type='str',),overwrite=dict(type='bool',)),
        class_list=dict(type='str',),
        glm_license=dict(type='str',),
        dnssec_ds=dict(type='str',),
        local_uri_file=dict(type='str',),
        wsdl=dict(type='str',),
        password=dict(type='str',),
        file_inspection_use_mgmt_port=dict(type='bool',),
        ssl_key=dict(type='str',),
        use_mgmt_port=dict(type='bool',),
        remote_file=dict(type='str',),
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
    payload = build_json("import", module)
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
    payload = build_json("import", module)
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