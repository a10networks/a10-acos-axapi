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
author: A10 Networks
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
    capture_config:
        description:
        - "Capture-config pcapng file"
        type: str
        required: False
    capture_config_realtime:
        description:
        - "Capture-config pcapng real-time file (For GUI)"
        type: str
        required: False
    pkt_count:
        description:
        - "Specify number of latest packets to export"
        type: int
        required: False
    debug_traffic_capture_chassis:
        description:
        - "Debug-Traffic-Capture pcapng file"
        type: str
        required: False
    debug_traffic_capture_chassis_slot:
        description:
        - "specify slot id in chassis"
        type: int
        required: False
    debug_traffic_capture:
        description:
        - "Debug-Traffic-Capture pcapng file"
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
    bw_list:
        description:
        - "Black white List File"
        type: str
        required: False
    class_list:
        description:
        - "Class List File"
        type: str
        required: False
    domain_list:
        description:
        - "Domain List File"
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
    ipsec_error_dump:
        description:
        - "IPsec error dump File"
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
    pktcapture_file:
        description:
        - "Enter Pktcapture file name"
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
    rpz:
        description:
        - "Response Policy Zone File"
        type: str
        required: False
    tsig:
        description:
        - "Transaction SIGnatures Key file"
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
    password:
        description:
        - "password for the remote site"
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
    geo_location_archive:
        description:
        - "Field geo_location_archive"
        type: dict
        required: False
        suboptions:
            geo_location_archive_name:
                description:
                - "'GeoLite2-ASN-Archive'= GeoLite2-ASN CSV Zipped File; 'GeoLite2-City-Archive'=
          GeoLite2-City CSV Zipped File; 'GeoLite2-Country-Archive'= GeoLite2-Country CSV
          Zipped File;"
                type: str
            use_mgmt_port:
                description:
                - "Use management port as source port"
                type: bool
            remote_file:
                description:
                - "Profile name for remote url"
                type: str
            password:
                description:
                - "password for the remote site"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "aflex", "auth_jwks", "auth_portal", "auth_portal_image", "axdebug", "bw_list", "ca_cert", "capture_config", "capture_config_realtime", "class_list", "csr", "debug_monitor", "debug_traffic_capture", "debug_traffic_capture_chassis", "debug_traffic_capture_chassis_slot", "dnssec_dnskey", "dnssec_ds", "domain_list", "externalfilename",
    "fixed_nat", "fixed_nat_archive", "geo_location", "geo_location_archive", "ip_map_list", "ipsec_error_dump", "local_uri_file", "lw_4o6", "lw_4o6_binding_table_validation_log", "merged_pcap", "mon_entity_debug_file", "password", "per_cpu", "pkt_count", "pktcapture_file", "profile", "remote_file", "rpz", "running_config", "saml_idp_name",
    "ssl_cert", "ssl_cert_key", "ssl_crl", "ssl_key", "startup_config", "status_check", "store", "store_name", "syslog", "tgz", "thales_kmdata", "thales_secworld", "tsig", "use_mgmt_port", "visibility", "xml_schema",
    ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'capture_config': {
            'type': 'str',
            },
        'capture_config_realtime': {
            'type': 'str',
            },
        'pkt_count': {
            'type': 'int',
            },
        'debug_traffic_capture_chassis': {
            'type': 'str',
            },
        'debug_traffic_capture_chassis_slot': {
            'type': 'int',
            },
        'debug_traffic_capture': {
            'type': 'str',
            },
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
        'bw_list': {
            'type': 'str',
            },
        'class_list': {
            'type': 'str',
            },
        'domain_list': {
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
        'ipsec_error_dump': {
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
        'pktcapture_file': {
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
        'rpz': {
            'type': 'str',
            },
        'tsig': {
            'type': 'str',
            },
        'use_mgmt_port': {
            'type': 'bool',
            },
        'remote_file': {
            'type': 'str',
            },
        'password': {
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
            },
        'geo_location_archive': {
            'type': 'dict',
            'geo_location_archive_name': {
                'type': 'str',
                'choices': ['GeoLite2-ASN-Archive', 'GeoLite2-City-Archive', 'GeoLite2-Country-Archive']
                },
            'use_mgmt_port': {
                'type': 'bool',
                },
            'remote_file': {
                'type': 'str',
                },
            'password': {
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


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/export"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["export"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["export"].get(k) != v:
            change_results["changed"] = True
            config_changes["export"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("export", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def run_command(module):
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        if state == 'present' or state == 'absent':
            existing_config = api_client.get(module.client, existing_url(module))
            result["axapi_calls"].append(existing_config)
            if existing_config['response_body'] != 'NotFound':
                existing_config = existing_config["response_body"]
            else:
                existing_config = None
        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["export"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["export-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
