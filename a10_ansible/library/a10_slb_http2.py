#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_http2
description:
    - Show http2 Statistics
short_description: Configures A10 slb.http2
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_proxy'= Curr Proxy Conns; 'total_proxy'= Total Proxy Conns; 'connection_preface_rcvd'= Connection preface rcvd; 'control_frame'= Control Frame Rcvd; 'headers_frame'= Headers Frame Rcvd; 'continuation_frame'= Cotinuaton Frame Rcvd; 'reset_frame'= RST Frame Rcvd; 'settings_frame'= Settings Frame Rcvd; 'window_update_frame'= Window Update Frame Rcvd; 'ping_frame'= Ping Frame Rcvd; 'goaway_frame'= Goaway Frame Rcvd; 'priority_frame'= Priority Frame Rcvd; 'data_frame'= Data Frame Recvd; 'unknown_frame'= Unknown Frame Recvd; 'connection_preface_sent'= Connection preface sent; 'settings_frame_sent'= Setting Frame Sent; 'settings_ack_sent'= Setting ACK Frame Sent; 'empty_settings_sent'= Empty Setting Frame Sent; 'ping_frame_sent'= Ping Frame Sent; 'window_update_frame_sent'= Window Update Frame Sent; 'rst_frame_sent'= RST Frame Sent; 'goaway_frame_sent'= GOAWAY Frame Sent; 'header_to_app'= Header Frame to HTTP; 'data_to_app'= Data Frame to HTTP; 'protocol_error'= Protocol Error; 'internal_error'= Internal Error; 'proxy_alloc_error'= HTTP2 Proxy alloc Error; 'split_buff_fail'= Splitting Buffer Failed; 'invalid_frame_size'= Invalid Frame Size Rcvd; 'control_frame_alloc_error'= Control Frame Alloc Failed; 'error_max_invalid_stream'= Max Invalid Stream Rcvd; 'data_no_stream'= Data Frame Rcvd on non-existent stream; 'flow_control_error'= Flow Control Error; 'settings_timeout'= Settings Timeout; 'frame_size_error'= Frame Size Error; 'refused_stream'= Refused Stream; 'cancel'= cancel; 'compression_error'= compression error; 'connect_error'= connect error; 'enhance_your_calm'= enhance your calm error; 'inadequate_security'= inadequate security; 'http_1_1_required'= HTTP1.1 Required; 'deflate_alloc_fail'= deflate alloc fail; 'inflate_alloc_fail'= inflate alloc fail; 'inflate_header_fail'= Inflate Header Fail; 'bad_connection_preface'= Bad Connection Preface; 'cant_allocate_control_frame'= Cant allocate control frame; 'cant_allocate_settings_frame'= Cant allocate settings frame; 'bad_frame_type_for_stream_state'= Bad frame type for stream state; 'wrong_stream_state'= Wrong Stream State; 'data_queue_alloc_error'= Data Queue Alloc Error; 'buff_alloc_error'= Buff alloc error; 'cant_allocate_rst_frame'= Cant allocate rst frame; 'cant_allocate_goaway_frame'= Cant allocate goaway frame; 'cant_allocate_ping_frame'= Cant allocate ping frame; 'cant_allocate_stream'= Cant allocate stream; 'cant_allocate_window_frame'= Cant allocate window frame; 'header_no_stream'= header no stream; 'header_padlen_gt_frame_payload'= Header padlen greater than frame payload size; 'streams_gt_max_concur_streams'= Streams greater than max allowed concurrent streams; 'idle_state_unexpected_frame'= Unxpected frame received in idle state; 'reserved_local_state_unexpected_frame'= Unexpected frame received in reserved local state; 'reserved_remote_state_unexpected_frame'= Unexpected frame received in reserved remote state; 'half_closed_remote_state_unexpected_frame'= Unexpected frame received in half closed remote state; 'closed_state_unexpected_frame'= Unexpected frame received in closed state; 'zero_window_size_on_stream'= Window Update with zero increment rcvd; 'exceeds_max_window_size_stream'= Window Update with increment that results in exceeding max window; 'stream_closed'= stream closed; 'continuation_before_headers'= continuation frame with no headers frame; 'invalid_frame_during_headers'= frame before headers were complete; 'headers_after_continuation'= headers frame before continuation was complete; 'invalid_push_promise'= unexpected push promise frame; 'invalid_stream_id'= received invalid stream ID; 'headers_interleaved'= headers interleaved on streams; 'trailers_no_end_stream'= trailers not marked as end-of-stream; 'invalid_setting_value'= invalid setting-frame value; 'invalid_window_update'= window-update value out of range; "
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
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_proxy','total_proxy','connection_preface_rcvd','control_frame','headers_frame','continuation_frame','reset_frame','settings_frame','window_update_frame','ping_frame','goaway_frame','priority_frame','data_frame','unknown_frame','connection_preface_sent','settings_frame_sent','settings_ack_sent','empty_settings_sent','ping_frame_sent','window_update_frame_sent','rst_frame_sent','goaway_frame_sent','header_to_app','data_to_app','protocol_error','internal_error','proxy_alloc_error','split_buff_fail','invalid_frame_size','control_frame_alloc_error','error_max_invalid_stream','data_no_stream','flow_control_error','settings_timeout','frame_size_error','refused_stream','cancel','compression_error','connect_error','enhance_your_calm','inadequate_security','http_1_1_required','deflate_alloc_fail','inflate_alloc_fail','inflate_header_fail','bad_connection_preface','cant_allocate_control_frame','cant_allocate_settings_frame','bad_frame_type_for_stream_state','wrong_stream_state','data_queue_alloc_error','buff_alloc_error','cant_allocate_rst_frame','cant_allocate_goaway_frame','cant_allocate_ping_frame','cant_allocate_stream','cant_allocate_window_frame','header_no_stream','header_padlen_gt_frame_payload','streams_gt_max_concur_streams','idle_state_unexpected_frame','reserved_local_state_unexpected_frame','reserved_remote_state_unexpected_frame','half_closed_remote_state_unexpected_frame','closed_state_unexpected_frame','zero_window_size_on_stream','exceeds_max_window_size_stream','stream_closed','continuation_before_headers','invalid_frame_during_headers','headers_after_continuation','invalid_push_promise','invalid_stream_id','headers_interleaved','trailers_no_end_stream','invalid_setting_value','invalid_window_update'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/http2"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/http2"

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
    payload = build_json("http2", module)
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
    payload = build_json("http2", module)
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
    payload = build_json("http2", module)
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