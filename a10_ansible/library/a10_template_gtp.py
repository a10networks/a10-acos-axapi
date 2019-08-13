#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_template_gtp
description:
    - Define a GTP template
short_description: Configures A10 template.gtp
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
    mandatory_ie_filtering:
        description:
        - "'disable'= Disable  Mandatory Information Element Filtering; "
        required: False
    name:
        description:
        - "GTP Template Name"
        required: True
    message_type:
        description:
        - "Field message_type"
        required: False
        suboptions:
            message_type_v2:
                description:
                - "'bearer-resource'= Bearer Resource Command/Failure; 'change-notification'= Change Notification Request/Response; 'context'= Context Request/Response/Ack; 'config-transfer'= Configuration Transfer Tunnel; 'create-bearer'= Create Bearer Request/Response; 'create-data-forwarding'= Create Indirect Data Tunnel Request/Response; 'create-tunnel-forwarding'= Create Forwarding Tunnel Request/Response; 'create-session'= Create Session Request/Response; 'cs-paging'= CS Paging Indication; 'delete-bearer'= Delete Bearer Request/Response; 'delete-command'= Delete Bearer Command/Failure; 'delete-data-forwarding'= Delete Indirect Data Tunnel Request/Response; 'delete-pdn'= Delete PDN Connection Request/Response; 'delete-session'= Delete Session Request/Response; 'detach'= Detach Notification/Ack; 'downlink-notification'= Downlink Data Notification/Ack/Failure; 'echo'= Echo Request/Response; 'fwd-access'= Forward Access Context Notification/Ack; 'fwd-relocation'= Forward Relocation Request/Response/Complete; 'identification'= Identification Request/Response; 'mbms-session-start'= MBMS Session Start Request/Response; 'mbms-session-stop'= MBMS Session Stop Request/Response; 'mbms-session-update'= MBMS Session Update Request/Response; 'modify-bearer'= Modify Bearer Request/Response; 'modify-command'= Modify Bearer Command/Failure; 'release-access'= Release Access Bearer Request/Response; 'relocation-cancel'= Relocation Cancel Request/Response; 'resume'= Resume Notification/Ack; 'stop-paging'= Stop Paging Indication; 'suspend'= Suspend Notification/Ack; 'trace-session'= Trace Session Activation/Deactivation; 'update-bearer'= Update Bearer Request/Response; 'update-pdn'= Update PDN Connection Request/Response; 'version-not-supported'= Version Not Supported; "
            drop_value:
                description:
                - "'drop'= Drop the Message Type; "
            message_type_v0:
                description:
                - "'create-pdp'= Create PDP Context Request/Response; 'data-record'= Data Record Request/Response; 'delete-pdp'= Delete PDP Context Request/Response; 'echo'= Echo Request/Response; 'error-indication'= Error Indication; 'failure-report'= Failure Report Request/Response; 'identification'= Identification Request/Response; 'node-alive'= Node Alive Request/Response; 'note-ms-present'= Note MS GPRS present Request/Response; 'pdu-notification'= PDU Notification Request/Response/Reject Request/Reject Response; 'redirection'= Redirection Request/Response; 'send-route'= Send Route Info Request/Response; 'sgsn-context'= Sgsn Context Request/Response/Acknowledge; 'gtp-pdu'= T-PDU; 'update-pdp'= Update PDP Context Request/Response; 'create-aa-pdp'= Create AA PDP Context Request/Response; 'delete-aa-pdp'= Delete AA PDP Context Request/Response; 'version-not-supported'= Version Not Supported; "
            message_type_v1:
                description:
                - "'create-pdp'= Create PDP Context Request/Response; 'data-record'= Data Record Request/Response; 'delete-pdp'= Delete PDP Context Request/Response; 'echo'= Echo Request/Response; 'error-indication'= Error Indication; 'failure-report'= Failure Report Request/Response; 'fwd-relocation'= Forward Relocation Request/Response/Complete/Complete Acknowledge; 'fwd-srns-context'= Forward Srns Context/Context Acknowlege; 'identification'= Identification Request/Response; 'node-alive'= Node Alive Request/Response; 'note-ms-present'= Note MS GPRS present Request/Response; 'pdu-notification'= PDU Notification Request/Response/Reject Request/Reject Response; 'ran-info'= RAN Info Relay; 'redirection'= Redirection Request/Response; 'relocation-cancel'= Relocation Cancel Request/Response; 'send-route'= Send Route Info Request/Response; 'sgsn-context'= Sgsn Context Request/Response/Acknowledge; 'supported-extension'= Supported Extension Headers Notification; 'gtp-pdu'= G-PDU; 'update-pdp'= Update PDP Context Request/Response; 'version-not-supported'= Version Not Supported; "
    user_tag:
        description:
        - "Customized tag"
        required: False
    log:
        description:
        - "Field log"
        required: False
        suboptions:
            message_filtering:
                description:
                - "Log Packet Drop due to Message Filtering"
            information_filtering:
                description:
                - "Log Packet Drop due to Information Filtering"
            mandatory_ie_missing:
                description:
                - "Log Packet Drop due to Missing Mandatory Information Element"
            invalid_teid:
                description:
                - "Log Packet Drop due to Invalid Tunnel Endpoint Identifier"
            reserved_ie_present:
                description:
                - "Log Packet Drop due to Presence of Reserved Information Element"
    tunnel_timeout:
        description:
        - "Idle Timeout in seconds (default= 5 mins)"
        required: False
    gtp_filter_list:
        description:
        - "Specify a GTP Filter-List (GTP Filter-List Value)"
        required: False
    maximum_message_length:
        description:
        - "Maximum message length for a GTP message"
        required: False
    protocol_anomaly_filtering:
        description:
        - "'disable'= Disable Anomaly Filtering; "
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
AVAILABLE_PROPERTIES = ["gtp_filter_list","log","mandatory_ie_filtering","maximum_message_length","message_type","name","protocol_anomaly_filtering","tunnel_timeout","user_tag","uuid",]

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
        mandatory_ie_filtering=dict(type='str',choices=['disable']),
        name=dict(type='str',required=True,),
        message_type=dict(type='list',message_type_v2=dict(type='str',choices=['bearer-resource','change-notification','context','config-transfer','create-bearer','create-data-forwarding','create-tunnel-forwarding','create-session','cs-paging','delete-bearer','delete-command','delete-data-forwarding','delete-pdn','delete-session','detach','downlink-notification','echo','fwd-access','fwd-relocation','identification','mbms-session-start','mbms-session-stop','mbms-session-update','modify-bearer','modify-command','release-access','relocation-cancel','resume','stop-paging','suspend','trace-session','update-bearer','update-pdn','version-not-supported']),drop_value=dict(type='str',choices=['drop']),message_type_v0=dict(type='str',choices=['create-pdp','data-record','delete-pdp','echo','error-indication','failure-report','identification','node-alive','note-ms-present','pdu-notification','redirection','send-route','sgsn-context','gtp-pdu','update-pdp','create-aa-pdp','delete-aa-pdp','version-not-supported']),message_type_v1=dict(type='str',choices=['create-pdp','data-record','delete-pdp','echo','error-indication','failure-report','fwd-relocation','fwd-srns-context','identification','node-alive','note-ms-present','pdu-notification','ran-info','redirection','relocation-cancel','send-route','sgsn-context','supported-extension','gtp-pdu','update-pdp','version-not-supported'])),
        user_tag=dict(type='str',),
        log=dict(type='dict',message_filtering=dict(type='bool',),information_filtering=dict(type='bool',),mandatory_ie_missing=dict(type='bool',),invalid_teid=dict(type='bool',),reserved_ie_present=dict(type='bool',)),
        tunnel_timeout=dict(type='int',),
        gtp_filter_list=dict(type='str',),
        maximum_message_length=dict(type='int',),
        protocol_anomaly_filtering=dict(type='str',choices=['disable']),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/template/gtp/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/template/gtp/{name}"

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("gtp", module)
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
    payload = build_json("gtp", module)
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
    payload = build_json("gtp", module)
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
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
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