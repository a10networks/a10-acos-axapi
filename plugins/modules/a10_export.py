#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_export
description:
    - Put files to remote site
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    axdebug:
        description:
        - "AX Debug Packet File"
        type: str
        required: False
    ssl_key:
        description:
        - "SSL Key File"
        type: str
        required: False
    ssl_crl:
        description:
        - "SSL Crl File"
        type: str
        required: False
    ssl_cert_key:
        description:
        - "Local SSL Key/Certificate file name"
        type: str
        required: False
    aflex:
        description:
        - "aFleX Script Source File"
        type: str
        required: False
    xml_schema:
        description:
        - "XML-Schema File"
        type: str
        required: False
    wsdl:
        description:
        - "Web Services Definition Language File"
        type: str
        required: False
    policy:
        description:
        - "WAF policy File"
        type: str
        required: False
    bw_list:
        description:
        - "Black white List File"
        type: str
        required: False
    file_inspection_bw_list:
        description:
        - "Black white List File"
        type: str
        required: False
    class_list:
        description:
        - "Class List File"
        type: str
        required: False
    lw_4o6:
        description:
        - "LW-4over6 Binding Table File"
        type: str
        required: False
    lw_4o6_binding_table_validation_log:
        description:
        - "LW-4over6 Binding Table Validation Log File"
        type: str
        required: False
    fixed_nat:
        description:
        - "Fixed NAT Port Mapping File"
        type: str
        required: False
    fixed_nat_archive:
        description:
        - "Fixed NAT Port Mapping Archive File"
        type: str
        required: False
    geo_location:
        description:
        - "Geo-location CSV File"
        type: str
        required: False
    dnssec_dnskey:
        description:
        - "DNSSEC DNSKEY(KSK) file for child zone"
        type: str
        required: False
    dnssec_ds:
        description:
        - "DNSSEC DS file for child zone"
        type: str
        required: False
    thales_secworld:
        description:
        - "Thales security world files"
        type: str
        required: False
    thales_kmdata:
        description:
        - "Thales Kmdata files"
        type: str
        required: False
    auth_portal:
        description:
        - "Portal file for http authentication"
        type: str
        required: False
    auth_portal_image:
        description:
        - "Image file for default portal"
        type: str
        required: False
    saml_idp_name:
        description:
        - "SAML metadata of identity provider"
        type: str
        required: False
    auth_jwks:
        description:
        - "Json web key"
        type: str
        required: False
    ip_map_list:
        description:
        - "IP Map List File"
        type: str
        required: False
    local_uri_file:
        description:
        - "Local URI files for http response"
        type: str
        required: False
    ssl_cert:
        description:
        - "SSL Cert File"
        type: str
        required: False
    ca_cert:
        description:
        - "CA Cert File"
        type: str
        required: False
    csr:
        description:
        - "Certificate Signing Request"
        type: str
        required: False
    debug_monitor:
        description:
        - "Debug Monitor Output"
        type: str
        required: False
    syslog:
        description:
        - "Enter 'messages' as the default syslog file name"
        type: str
        required: False
    running_config:
        description:
        - "Running Config"
        type: bool
        required: False
    startup_config:
        description:
        - "Startup Config"
        type: bool
        required: False
    visibility:
        description:
        - "Export Visibility module related files"
        type: bool
        required: False
    mon_entity_debug_file:
        description:
        - "Enter Mon entity debug file name"
        type: str
        required: False
    profile:
        description:
        - "Startup-config Profile"
        type: str
        required: False
    status_check:
        description:
        - "check export task status"
        type: bool
        required: False
    merged_pcap:
        description:
        - "Export the merged pcap file when there are multiple Export sessions"
        type: bool
        required: False
    per_cpu:
        description:
        - "Export the per-cpu files along with the merged pcap file in .tgz format"
        type: bool
        required: False
    tgz:
        description:
        - "Export the merged pcap in .tgz format"
        type: bool
        required: False
    externalfilename:
        description:
        - "Export the External Program from the System"
        type: str
        required: False
    use_mgmt_port:
        description:
        - "Use management port as source port"
        type: bool
        required: False
    remote_file:
        description:
        - "profile name for remote url"
        type: str
        required: False
    store_name:
        description:
        - "Export store name"
        type: str
        required: False
    store:
        description:
        - "Field store"
        type: dict
        required: False
        suboptions:
            delete:
                description:
                - "Delete an export store profile"
                type: bool
            create:
                description:
                - "Create an export store profile"
                type: bool
            name:
                description:
                - "profile name to store remote url"
                type: str
            remote_file:
                description:
                - "Field remote_file"
                type: str

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "aflex",
    "auth_jwks",
    "auth_portal",
    "auth_portal_image",
    "axdebug",
    "bw_list",
    "ca_cert",
    "class_list",
    "csr",
    "debug_monitor",
    "dnssec_dnskey",
    "dnssec_ds",
    "externalfilename",
    "file_inspection_bw_list",
    "fixed_nat",
    "fixed_nat_archive",
    "geo_location",
    "ip_map_list",
    "local_uri_file",
    "lw_4o6",
    "lw_4o6_binding_table_validation_log",
    "merged_pcap",
    "mon_entity_debug_file",
    "per_cpu",
    "policy",
    "profile",
    "remote_file",
    "running_config",
    "saml_idp_name",
    "ssl_cert",
    "ssl_cert_key",
    "ssl_crl",
    "ssl_key",
    "startup_config",
    "status_check",
    "store",
    "store_name",
    "syslog",
    "tgz",
    "thales_kmdata",
    "thales_secworld",
    "use_mgmt_port",
    "visibility",
    "wsdl",
    "xml_schema",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'axdebug': {
            'type': 'str',
        },
        'ssl_key': {
            'type': 'str',
        },
        'ssl_crl': {
            'type': 'str',
        },
        'ssl_cert_key': {
            'type': 'str',
        },
        'aflex': {
            'type': 'str',
        },
        'xml_schema': {
            'type': 'str',
        },
        'wsdl': {
            'type': 'str',
        },
        'policy': {
            'type': 'str',
        },
        'bw_list': {
            'type': 'str',
        },
        'file_inspection_bw_list': {
            'type': 'str',
        },
        'class_list': {
            'type': 'str',
        },
        'lw_4o6': {
            'type': 'str',
        },
        'lw_4o6_binding_table_validation_log': {
            'type': 'str',
        },
        'fixed_nat': {
            'type': 'str',
        },
        'fixed_nat_archive': {
            'type': 'str',
        },
        'geo_location': {
            'type': 'str',
        },
        'dnssec_dnskey': {
            'type': 'str',
        },
        'dnssec_ds': {
            'type': 'str',
        },
        'thales_secworld': {
            'type': 'str',
        },
        'thales_kmdata': {
            'type': 'str',
        },
        'auth_portal': {
            'type': 'str',
        },
        'auth_portal_image': {
            'type': 'str',
        },
        'saml_idp_name': {
            'type': 'str',
        },
        'auth_jwks': {
            'type': 'str',
        },
        'ip_map_list': {
            'type': 'str',
        },
        'local_uri_file': {
            'type': 'str',
        },
        'ssl_cert': {
            'type': 'str',
        },
        'ca_cert': {
            'type': 'str',
        },
        'csr': {
            'type': 'str',
        },
        'debug_monitor': {
            'type': 'str',
        },
        'syslog': {
            'type': 'str',
        },
        'running_config': {
            'type': 'bool',
        },
        'startup_config': {
            'type': 'bool',
        },
        'visibility': {
            'type': 'bool',
        },
        'mon_entity_debug_file': {
            'type': 'str',
        },
        'profile': {
            'type': 'str',
        },
        'status_check': {
            'type': 'bool',
        },
        'merged_pcap': {
            'type': 'bool',
        },
        'per_cpu': {
            'type': 'bool',
        },
        'tgz': {
            'type': 'bool',
        },
        'externalfilename': {
            'type': 'str',
        },
        'use_mgmt_port': {
            'type': 'bool',
        },
        'remote_file': {
            'type': 'str',
        },
        'store_name': {
            'type': 'str',
        },
        'store': {
            'type': 'dict',
            'delete': {
                'type': 'bool',
            },
            'create': {
                'type': 'bool',
            },
            'name': {
                'type': 'str',
            },
            'remote_file': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/export"

    f_dict = {}

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
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


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/export"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
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


def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["export"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["export"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["export"][k] = v
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
    payload = build_json("export", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result


def run_command(module):
    run_errors = []

    result = dict(changed=False, original_message="", message="", result={})

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
