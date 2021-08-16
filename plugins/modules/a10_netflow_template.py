#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_netflow_template
description:
    - IPFIX Custom Template
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
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
    name:
        description:
        - "IPFIX CUSTOM Template Name"
        type: str
        required: True
    information_element_blk:
        description:
        - "Field information_element_blk"
        type: list
        required: False
        suboptions:
            information_element:
                description:
                - "'fwd-tuple-vnp-id'= Session forward tuple partition id (ID= 33028); 'rev-tuple-
          vnp-id'= Session reverse tuple partition id (ID= 33029); 'source-ipv4-address'=
          IPv4 source address in the IP packet header (ID= 8); 'dest-ipv4-address'= IPv4
          destination address in the IP packet header (ID= 12); 'source-ipv6-address'=
          IPv6 source address in the IP packet header (ID= 27); 'dest-ipv6-address'= IPv6
          destination address in the IP packet header (ID=28); 'post-nat-source-
          ipv4-address'= IPv4 natted source address (ID= 225); 'post-nat-dest-
          ipv4-address'= IPv4 natted destination address(ID= 226); 'post-nat-source-
          ipv6-address'= IPv6 natted source address (ID= 281); 'post-nat-dest-
          ipv6-address'= IPv6 natted destination address (ID= 282); 'source-port'= Source
          port identifier in the transport header (ID= 7); 'dest-port'= Destination port
          identifier in the transport header (ID= 11); 'post-nat-source-port'= L4 natted
          source port(ID= 227); 'post-nat-dest-port'= L4 natted destination port (ID=
          228); 'fwd-tuple-type'= Session forward tuple type (ID= 33024); 'rev-tuple-
          type'= Session reverse tuple type (ID= 33025); 'ip-proto'= Value of the
          protocol number in the IP packet header (ID= 4); 'flow-direction'= Flow
          direction= 0=inbound(To an outside interface)/1=outbound(To an inside
          interface) (ID= 61); 'tcp-control-bits'= Cumulative of all the TCP flags seen
          for this flow (ID= 6); 'fwd-bytes'= Incoming bytes associated with an IP Flow
          (ID= 1); 'fwd-packets'= Incoming packets associated with an IP Flow (ID= 2);
          'rev-bytes'= Delta bytes in reverse direction of bidirectional flow record (ID=
          32769); 'rev-packets'= Delta packets in reverse direction of bidirectional flow
          record (ID= 32770); 'in-port'= Incoming interface port (ID= 10); 'out-port'=
          Outcoming interface port (ID= 14); 'in-interface'= Incoming interface name e.g.
          ethernet 0 (ID= 82); 'out-interface'= Outcoming interface name e.g. ethernet 0
          (ID= 32850); 'port-range-start'= Port number identifying the start of a range
          of ports (ID= 361); 'port-range-end'= Port number identifying the end of a
          range of ports (ID= 362); 'port-range-step-size'= Step size in a port range
          (ID= 363); 'port-range-num-ports'= Number of ports in a port range (ID= 364);
          'rule-name'= Rule Name (ID= 33034); 'rule-set-name'= Rule-Set Name (ID= 33035);
          'fw-source-zone'= Firewall Source Zone Name (ID= 33036); 'fw-dest-zone'=
          Firewall Dest Zone Name (ID= 33037); 'application-id'= Application ID (ID= 95);
          'radius-imsi'= Radius Attribute IMSI (ID= 455); 'radius-msisdn'= Radius
          Attribute MSISDN (ID= 456); 'radius-imei'= Radius Attribute IMEI (ID= 33030);
          'radius-custom1'= Radius Attribute Custom 1 (ID= 33031); 'radius-custom2'=
          Radius Attribute Custom 2(ID= 33032); 'radius-custom3'= Radius Attribute Custom
          3 (ID=33033); 'flow-start-msec'= The absolute timestamp of the first packet of
          the flow (ID= 152); 'flow-duration-msec'= Difference in time between the first
          observed packet of this flow and the last observed packet of this flow (4
          bytes) (ID= 161); 'flow-duration-msec-64'= Difference in time between the first
          observed packet of this flow and the last observed packet of this flow (8
          bytes) (ID= 33039); 'nat-event'= Indicates a NAT event (ID= 230); 'fw-event'=
          Indicates a FW session event(ID= 233); 'fw-deny-reset-event'= Indicates a FW
          deny/reset event (ID= 33038); 'cgn-flow-direction'= Flow direction=
          0=inbound(To an outside interface)/1=outbound(To an inside
          interface)/2=hairpin(From an inside interface to an inside interface) (ID=
          33040); 'fw-dest-fqdn'= Firewall matched fqdn(ID= 33041); 'flow-end-reason'=
          A10 flow end reason(ID= 33042); 'event-time-msec'= The absolute time in
          milliseconds of an event observation(ID= 323);"
                type: str
    ipfix_template_id:
        description:
        - "Custom IPFIX Template ID"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False

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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "information_element_blk",
    "ipfix_template_id",
    "name",
    "user_tag",
    "uuid",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='str',
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'information_element_blk': {
            'type': 'list',
            'information_element': {
                'type':
                'str',
                'choices': [
                    'fwd-tuple-vnp-id', 'rev-tuple-vnp-id',
                    'source-ipv4-address', 'dest-ipv4-address',
                    'source-ipv6-address', 'dest-ipv6-address',
                    'post-nat-source-ipv4-address',
                    'post-nat-dest-ipv4-address',
                    'post-nat-source-ipv6-address',
                    'post-nat-dest-ipv6-address', 'source-port', 'dest-port',
                    'post-nat-source-port', 'post-nat-dest-port',
                    'fwd-tuple-type', 'rev-tuple-type', 'ip-proto',
                    'flow-direction', 'tcp-control-bits', 'fwd-bytes',
                    'fwd-packets', 'rev-bytes', 'rev-packets', 'in-port',
                    'out-port', 'in-interface', 'out-interface',
                    'port-range-start', 'port-range-end',
                    'port-range-step-size', 'port-range-num-ports',
                    'rule-name', 'rule-set-name', 'fw-source-zone',
                    'fw-dest-zone', 'application-id', 'radius-imsi',
                    'radius-msisdn', 'radius-imei', 'radius-custom1',
                    'radius-custom2', 'radius-custom3', 'flow-start-msec',
                    'flow-duration-msec', 'flow-duration-msec-64', 'nat-event',
                    'fw-event', 'fw-deny-reset-event', 'cgn-flow-direction',
                    'fw-dest-fqdn', 'flow-end-reason', 'event-time-msec'
                ]
            }
        },
        'ipfix_template_id': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/netflow/template/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


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
    url_base = "/axapi/v3/netflow/template/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["template"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["template"].get(k) != v:
            change_results["changed"] = True
            config_changes["template"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("template", module)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    run_errors = []
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
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
    result["axapi_calls"].append(existing_config)
    if existing_config['response_body'] != 'Not Found':
        existing_config = existing_config["response_body"]
    else:
        existing_config = None

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
