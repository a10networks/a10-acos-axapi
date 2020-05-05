#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_dnssec
description:
    - Domain Name System Security Extensions commands
short_description: Configures A10 dnssec
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            ptr_memory:
                description:
                - "Field ptr_memory"
            total_memory:
                description:
                - "Field total_memory"
            reference_objects:
                description:
                - "Field reference_objects"
            cname_memory:
                description:
                - "Field cname_memory"
            ds_objects:
                description:
                - "Field ds_objects"
            nsec_objects:
                description:
                - "Field nsec_objects"
            array_memory:
                description:
                - "Field array_memory"
            nsec3param_objects:
                description:
                - "Field nsec3param_objects"
            srv_memory:
                description:
                - "Field srv_memory"
            reference_memory:
                description:
                - "Field reference_memory"
            a_memory:
                description:
                - "Field a_memory"
            table_memory:
                description:
                - "Field table_memory"
            a_objects:
                description:
                - "Field a_objects"
            ns_memory:
                description:
                - "Field ns_memory"
            aaaa_memory:
                description:
                - "Field aaaa_memory"
            zone_objects:
                description:
                - "Field zone_objects"
            table_objects:
                description:
                - "Field table_objects"
            mx_memory:
                description:
                - "Field mx_memory"
            soa_memory:
                description:
                - "Field soa_memory"
            domain_objects:
                description:
                - "Field domain_objects"
            nsec_memory:
                description:
                - "Field nsec_memory"
            nsec3_objects:
                description:
                - "Field nsec3_objects"
            srv_objects:
                description:
                - "Field srv_objects"
            array_objects:
                description:
                - "Field array_objects"
            ns_objects:
                description:
                - "Field ns_objects"
            soa_objects:
                description:
                - "Field soa_objects"
            ds_memory:
                description:
                - "Field ds_memory"
            cname_objects:
                description:
                - "Field cname_objects"
            domain_memory:
                description:
                - "Field domain_memory"
            nsec3param_memory:
                description:
                - "Field nsec3param_memory"
            txt_memory:
                description:
                - "Field txt_memory"
            dnskey_memory:
                description:
                - "Field dnskey_memory"
            total_objects:
                description:
                - "Field total_objects"
            ptr_objects:
                description:
                - "Field ptr_objects"
            aaaa_objects:
                description:
                - "Field aaaa_objects"
            mx_objects:
                description:
                - "Field mx_objects"
            txt_objects:
                description:
                - "Field txt_objects"
            rrsig_objects:
                description:
                - "Field rrsig_objects"
            rrsig2_memory:
                description:
                - "Field rrsig2_memory"
            nsec3_memory:
                description:
                - "Field nsec3_memory"
            zone_memory:
                description:
                - "Field zone_memory"
            rrsig2_objects:
                description:
                - "Field rrsig2_objects"
            rrsig_memory:
                description:
                - "Field rrsig_memory"
            dnskey_objects:
                description:
                - "Field dnskey_objects"
    key_rollover:
        description:
        - "Field key_rollover"
        required: False
        suboptions:
            dnssec_key_type:
                description:
                - "'ZSK'= Zone Signing Key; 'KSK'= Key Signing Key; "
            zsk_start:
                description:
                - "start ZSK rollover in emergency mode"
            ksk_start:
                description:
                - "start KSK rollover in emergency mode"
            ds_ready_in_parent_zone:
                description:
                - "DS RR is already ready in the parent zone"
            zone_name:
                description:
                - "Specify the name for the DNS zone"
    standalone:
        description:
        - "Run DNSSEC in standalone mode, in GSLB group mode by default"
        required: False
    sign_zone_now:
        description:
        - "Field sign_zone_now"
        required: False
        suboptions:
            zone_name:
                description:
                - "Specify the name for the DNS zone, empty means sign all zones"
    dnskey:
        description:
        - "Field dnskey"
        required: False
        suboptions:
            key_delete:
                description:
                - "Delete the DNSKEY file"
            zone_name:
                description:
                - "DNS zone name of the child zone"
    template_list:
        description:
        - "Field template_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            algorithm:
                description:
                - "'RSASHA1'= RSASHA1 algorithm; 'RSASHA256'= RSASHA256 algorithm; 'RSASHA512'= RSASHA512 algorithm; "
            combinations_limit:
                description:
                - "the max number of combinations per RRset (Default value is 31)"
            dnskey_ttl_k:
                description:
                - "The TTL value of DNSKEY RR"
            user_tag:
                description:
                - "Customized tag"
            hsm:
                description:
                - "specify the HSM template"
            enable_nsec3:
                description:
                - "enable NSEC3 support. disabled by default"
            return_nsec_on_failure:
                description:
                - "return NSEC/NSEC3 or not on failure case. return by default"
            dnskey_ttl_v:
                description:
                - "in seconds, 14400 seconds by default"
            signature_validity_period_k:
                description:
                - "The period that a signature is valid"
            dnssec_template_ksk:
                description:
                - "Field dnssec_template_ksk"
            dnssec_template_zsk:
                description:
                - "Field dnssec_template_zsk"
            signature_validity_period_v:
                description:
                - "in days, 10 days by default"
            dnssec_temp_name:
                description:
                - "DNSSEC Template Name"
    ds:
        description:
        - "Field ds"
        required: False
        suboptions:
            ds_delete:
                description:
                - "Delete the DS file"
            zone_name:
                description:
                - "DNS zone name of the child zone"
    uuid:
        description:
        - "uuid of the object"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["dnskey","ds","key_rollover","oper","sign_zone_now","standalone","template_list","uuid",]

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
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', ptr_memory=dict(type='int', ), total_memory=dict(type='int', ), reference_objects=dict(type='int', ), cname_memory=dict(type='int', ), ds_objects=dict(type='int', ), nsec_objects=dict(type='int', ), array_memory=dict(type='int', ), nsec3param_objects=dict(type='int', ), srv_memory=dict(type='int', ), reference_memory=dict(type='int', ), a_memory=dict(type='int', ), table_memory=dict(type='int', ), a_objects=dict(type='int', ), ns_memory=dict(type='int', ), aaaa_memory=dict(type='int', ), zone_objects=dict(type='int', ), table_objects=dict(type='int', ), mx_memory=dict(type='int', ), soa_memory=dict(type='int', ), domain_objects=dict(type='int', ), nsec_memory=dict(type='int', ), nsec3_objects=dict(type='int', ), srv_objects=dict(type='int', ), array_objects=dict(type='int', ), ns_objects=dict(type='int', ), soa_objects=dict(type='int', ), ds_memory=dict(type='int', ), cname_objects=dict(type='int', ), domain_memory=dict(type='int', ), nsec3param_memory=dict(type='int', ), txt_memory=dict(type='int', ), dnskey_memory=dict(type='int', ), total_objects=dict(type='int', ), ptr_objects=dict(type='int', ), aaaa_objects=dict(type='int', ), mx_objects=dict(type='int', ), txt_objects=dict(type='int', ), rrsig_objects=dict(type='int', ), rrsig2_memory=dict(type='int', ), nsec3_memory=dict(type='int', ), zone_memory=dict(type='int', ), rrsig2_objects=dict(type='int', ), rrsig_memory=dict(type='int', ), dnskey_objects=dict(type='int', )),
        key_rollover=dict(type='dict', dnssec_key_type=dict(type='str', choices=['ZSK', 'KSK']), zsk_start=dict(type='bool', ), ksk_start=dict(type='bool', ), ds_ready_in_parent_zone=dict(type='bool', ), zone_name=dict(type='str', )),
        standalone=dict(type='bool', ),
        sign_zone_now=dict(type='dict', zone_name=dict(type='str', )),
        dnskey=dict(type='dict', key_delete=dict(type='bool', ), zone_name=dict(type='str', )),
        template_list=dict(type='list', uuid=dict(type='str', ), algorithm=dict(type='str', choices=['RSASHA1', 'RSASHA256', 'RSASHA512']), combinations_limit=dict(type='int', ), dnskey_ttl_k=dict(type='bool', ), user_tag=dict(type='str', ), hsm=dict(type='str', ), enable_nsec3=dict(type='bool', ), return_nsec_on_failure=dict(type='bool', ), dnskey_ttl_v=dict(type='int', ), signature_validity_period_k=dict(type='bool', ), dnssec_template_ksk=dict(type='dict', ksk_keysize_k=dict(type='bool', ), zsk_rollover_time_v=dict(type='int', ), ksk_keysize_v=dict(type='int', ), ksk_lifetime_v=dict(type='int', ), ksk_rollover_time_k=dict(type='bool', ), ksk_lifetime_k=dict(type='bool', )), dnssec_template_zsk=dict(type='dict', zsk_keysize_v=dict(type='int', ), zsk_rollover_time_v=dict(type='int', ), zsk_lifetime_v=dict(type='int', ), zsk_lifetime_k=dict(type='bool', ), zsk_keysize_k=dict(type='bool', ), zsk_rollover_time_k=dict(type='bool', )), signature_validity_period_v=dict(type='int', ), dnssec_temp_name=dict(type='str', required=True, )),
        ds=dict(type='dict', ds_delete=dict(type='bool', ), zone_name=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/dnssec"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/dnssec"

    f_dict = {}

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

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
    if module.params.get("oper"):
        query_params = {}
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
    return module.client.get(oper_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["dnssec"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["dnssec"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["dnssec"][k] = v
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
    payload = build_json("dnssec", module)
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

def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
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
    a10_device_context_id = module.params["a10_device_context_id"]

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

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
    elif state == 'absent':
        result = absent(module, result, existing_config)
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
    module.client.session.close()
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