#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_fw_radius_server
description:
    - Configure system as a RADIUS server
short_description: Configures A10 fw.radius.server
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
    accounting_start:
        description:
        - "'ignore'= Ignore; 'append-entry'= Append the AVPs to existing entry (default); 'replace-entry'= Replace the AVPs of existing entry; "
        required: False
    attribute_name:
        description:
        - "'msisdn'= Clear using MSISDN; 'imei'= Clear using IMEI; 'imsi'= Clear using IMSI; "
        required: False
    vrid:
        description:
        - "Join a VRRP-A failover group"
        required: False
    remote:
        description:
        - "Field remote"
        required: False
        suboptions:
            ip_list:
                description:
                - "Field ip_list"
    uuid:
        description:
        - "uuid of the object"
        required: False
    encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED secret string)"
        required: False
    accounting_interim_update:
        description:
        - "'ignore'= Ignore (default); 'append-entry'= Append the AVPs to existing entry; 'replace-entry'= Replace the AVPs of existing entry; "
        required: False
    secret:
        description:
        - "Configure shared secret"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'msisdn-received'= MSISDN Received; 'imei-received'= IMEI Received; 'imsi-received'= IMSI Received; 'custom-received'= Custom attribute Received; 'radius-request-received'= RADIUS Request Received; 'radius-request-dropped'= RADIUS Request Dropped (Malformed Packet); 'request-bad-secret-dropped'= RADIUS Request Bad Secret Dropped; 'request-no-key-vap-dropped'= RADIUS Request No Key Attribute Dropped; 'request-malformed-dropped'= RADIUS Request Malformed Dropped; 'request-ignored'= RADIUS Request Table Full Dropped; 'radius-table-full'= RADIUS Request Dropped (Table Full); 'secret-not-configured-dropped'= RADIUS Secret Not Configured Dropped; 'ha-standby-dropped'= HA Standby Dropped; 'ipv6-prefix-length-mismatch'= Framed IPV6 Prefix Length Mismatch; 'invalid-key'= Radius Request has Invalid Key Field; 'smp-mem-allocated'= RADIUS SMP Memory Allocated; 'smp-mem-alloc-failed'= RADIUS SMP Memory Allocation Failed; 'smp-mem-freed'= RADIUS SMP Memory Freed; 'smp-created'= RADIUS SMP Created; 'smp-in-rml'= RADIUS SMP in RML; 'smp-deleted'= RADIUS SMP Deleted; 'mem-allocated'= RADIUS Memory Allocated; 'mem-alloc-failed'= RADIUS Memory Allocation Failed; 'mem-freed'= RADIUS Memory Freed; 'ha-sync-create-sent'= HA Record Sync Create Sent; 'ha-sync-delete-sent'= HA Record Sync Delete Sent; 'ha-sync-create-recv'= HA Record Sync Create Received; 'ha-sync-delete-recv'= HA Record Sync Delete Received; 'acct-on-filters-full'= RADIUS Acct On Request Ignored(Filters Full); 'acct-on-dup-request'= Duplicate RADIUS Acct On Request; 'ip-mismatch-delete'= Radius Entry IP Mismatch Delete; 'ip-add-race-drop'= Radius Entry IP Add Race Drop; 'ha-sync-no-key-vap-dropped'= HA Record Sync No key dropped; 'inter-card-msg-fail-drop'= Inter-Card Message Fail Drop; "
    accounting_stop:
        description:
        - "'ignore'= Ignore; 'delete-entry'= Delete the entry (default); "
        required: False
    custom_attribute_name:
        description:
        - "Clear using customized attribute"
        required: False
    attribute:
        description:
        - "Field attribute"
        required: False
        suboptions:
            prefix_number:
                description:
                - "RADIUS attribute number"
            prefix_length:
                description:
                - "'32'= Prefix length 32; '48'= Prefix length 48; '64'= Prefix length 64; '80'= Prefix length 80; '96'= Prefix length 96; '112'= Prefix length 112; "
            name:
                description:
                - "Customized attribute name"
            prefix_vendor:
                description:
                - "RADIUS vendor attribute information (RADIUS vendor ID)"
            number:
                description:
                - "RADIUS attribute number"
            value:
                description:
                - "'hexadecimal'= Type of attribute value is hexadecimal; "
            custom_vendor:
                description:
                - "RADIUS vendor attribute information (RADIUS vendor ID)"
            custom_number:
                description:
                - "RADIUS attribute number"
            vendor:
                description:
                - "RADIUS vendor attribute information (RADIUS vendor ID)"
            attribute_value:
                description:
                - "'inside-ipv6-prefix'= Framed IPv6 Prefix; 'inside-ip'= Inside IP address; 'inside-ipv6'= Inside IPv6 address; 'imei'= International Mobile Equipment Identity (IMEI); 'imsi'= International Mobile Subscriber Identity (IMSI); 'msisdn'= Mobile Subscriber Integrated Services Digital Network-Number (MSISDN); 'custom1'= Customized attribute 1; 'custom2'= Customized attribute 2; 'custom3'= Customized attribute 3; "
    listen_port:
        description:
        - "Configure the listen port of RADIUS server (Port number)"
        required: False
    accounting_on:
        description:
        - "'ignore'= Ignore (default); 'delete-entries-using-attribute'= Delete entries matching attribute in RADIUS Table; "
        required: False
    secret_string:
        description:
        - "The RADIUS secret"
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
AVAILABLE_PROPERTIES = ["accounting_interim_update","accounting_on","accounting_start","accounting_stop","attribute","attribute_name","custom_attribute_name","encrypted","listen_port","remote","sampling_enable","secret","secret_string","uuid","vrid",]

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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        accounting_start=dict(type='str',choices=['ignore','append-entry','replace-entry']),
        attribute_name=dict(type='str',choices=['msisdn','imei','imsi']),
        vrid=dict(type='int',),
        remote=dict(type='dict',ip_list=dict(type='list',ip_list_name=dict(type='str',),ip_list_encrypted=dict(type='str',),ip_list_secret_string=dict(type='str',),ip_list_secret=dict(type='bool',))),
        uuid=dict(type='str',),
        encrypted=dict(type='str',),
        accounting_interim_update=dict(type='str',choices=['ignore','append-entry','replace-entry']),
        secret=dict(type='bool',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','msisdn-received','imei-received','imsi-received','custom-received','radius-request-received','radius-request-dropped','request-bad-secret-dropped','request-no-key-vap-dropped','request-malformed-dropped','request-ignored','radius-table-full','secret-not-configured-dropped','ha-standby-dropped','ipv6-prefix-length-mismatch','invalid-key','smp-mem-allocated','smp-mem-alloc-failed','smp-mem-freed','smp-created','smp-in-rml','smp-deleted','mem-allocated','mem-alloc-failed','mem-freed','ha-sync-create-sent','ha-sync-delete-sent','ha-sync-create-recv','ha-sync-delete-recv','acct-on-filters-full','acct-on-dup-request','ip-mismatch-delete','ip-add-race-drop','ha-sync-no-key-vap-dropped','inter-card-msg-fail-drop'])),
        accounting_stop=dict(type='str',choices=['ignore','delete-entry']),
        custom_attribute_name=dict(type='str',),
        attribute=dict(type='list',prefix_number=dict(type='int',),prefix_length=dict(type='str',choices=['32','48','64','80','96','112']),name=dict(type='str',),prefix_vendor=dict(type='int',),number=dict(type='int',),value=dict(type='str',choices=['hexadecimal']),custom_vendor=dict(type='int',),custom_number=dict(type='int',),vendor=dict(type='int',),attribute_value=dict(type='str',choices=['inside-ipv6-prefix','inside-ip','inside-ipv6','imei','imsi','msisdn','custom1','custom2','custom3'])),
        listen_port=dict(type='int',),
        accounting_on=dict(type='str',choices=['ignore','delete-entries-using-attribute']),
        secret_string=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/radius/server"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/radius/server"

    f_dict = {}

    return url_base.format(**f_dict)

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
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("server", module)
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
    payload = build_json("server", module)
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
    payload = build_json("server", module)
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
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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