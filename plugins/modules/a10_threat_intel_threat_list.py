#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_threat_intel_threat_list
description:
    - Threat Categories for malicious IPs
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
        - "Threat category List name"
        type: str
        required: True
    ntype:
        description:
        - "'webroot'= Configure Webroot threat categories;"
        type: str
        required: False
    all_categories:
        description:
        - "Enable all categories"
        type: bool
        required: False
    spam_sources:
        description:
        - "IP's tunneling spam messages through a proxy, anomalous SMTP activities, and
          forum spam activities"
        type: bool
        required: False
    windows_exploits:
        description:
        - "IP's associated with malware, shell code, rootkits, worms or viruses"
        type: bool
        required: False
    web_attacks:
        description:
        - "IP's associated with cross site scripting, iFrame injection, SQL injection,
          cross domain injection, or domain password brute fo"
        type: bool
        required: False
    botnets:
        description:
        - "Botnet C&C channels, and infected zombie machines controlled by Bot master"
        type: bool
        required: False
    scanners:
        description:
        - "IP's associated with probes, host scan, domain scan, and password brute force
          attack"
        type: bool
        required: False
    dos_attacks:
        description:
        - "IP's participating in DOS, DDOS, anomalous sync flood, and anomalous traffic
          detection"
        type: bool
        required: False
    reputation:
        description:
        - "IP addresses currently known to be infected with malware"
        type: bool
        required: False
    phishing:
        description:
        - "IP addresses hosting phishing sites, ad click fraud or gaming fraud"
        type: bool
        required: False
    proxy:
        description:
        - "IP addresses providing proxy services"
        type: bool
        required: False
    mobile_threats:
        description:
        - "IP's associated with mobile threats"
        type: bool
        required: False
    tor_proxy:
        description:
        - "IP's providing tor proxy services"
        type: bool
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'spam-sources'= Hits for spam sources; 'windows-exploits'= Hits for
          windows exploits; 'web-attacks'= Hits for web attacks; 'botnets'= Hits for
          botnets; 'scanners'= Hits for scanners; 'dos-attacks'= Hits for dos attacks;
          'reputation'= Hits for reputation; 'phishing'= Hits for phishing; 'proxy'= Hits
          for proxy; 'mobile-threats'= Hits for mobile threats; 'tor-proxy'= Hits for
          tor-proxy; 'total-hits'= Total hits for threat-list;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            spam_sources:
                description:
                - "Hits for spam sources"
                type: str
            windows_exploits:
                description:
                - "Hits for windows exploits"
                type: str
            web_attacks:
                description:
                - "Hits for web attacks"
                type: str
            botnets:
                description:
                - "Hits for botnets"
                type: str
            scanners:
                description:
                - "Hits for scanners"
                type: str
            dos_attacks:
                description:
                - "Hits for dos attacks"
                type: str
            reputation:
                description:
                - "Hits for reputation"
                type: str
            phishing:
                description:
                - "Hits for phishing"
                type: str
            proxy:
                description:
                - "Hits for proxy"
                type: str
            mobile_threats:
                description:
                - "Hits for mobile threats"
                type: str
            tor_proxy:
                description:
                - "Hits for tor-proxy"
                type: str
            total_hits:
                description:
                - "Total hits for threat-list"
                type: str
            name:
                description:
                - "Threat category List name"
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
    "all_categories",
    "botnets",
    "dos_attacks",
    "mobile_threats",
    "name",
    "phishing",
    "proxy",
    "reputation",
    "sampling_enable",
    "scanners",
    "spam_sources",
    "stats",
    "tor_proxy",
    "ntype",
    "user_tag",
    "uuid",
    "web_attacks",
    "windows_exploits",
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
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'ntype': {
            'type': 'str',
            'choices': ['webroot']
        },
        'all_categories': {
            'type': 'bool',
        },
        'spam_sources': {
            'type': 'bool',
        },
        'windows_exploits': {
            'type': 'bool',
        },
        'web_attacks': {
            'type': 'bool',
        },
        'botnets': {
            'type': 'bool',
        },
        'scanners': {
            'type': 'bool',
        },
        'dos_attacks': {
            'type': 'bool',
        },
        'reputation': {
            'type': 'bool',
        },
        'phishing': {
            'type': 'bool',
        },
        'proxy': {
            'type': 'bool',
        },
        'mobile_threats': {
            'type': 'bool',
        },
        'tor_proxy': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'spam-sources', 'windows-exploits', 'web-attacks',
                    'botnets', 'scanners', 'dos-attacks', 'reputation',
                    'phishing', 'proxy', 'mobile-threats', 'tor-proxy',
                    'total-hits'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'spam_sources': {
                'type': 'str',
            },
            'windows_exploits': {
                'type': 'str',
            },
            'web_attacks': {
                'type': 'str',
            },
            'botnets': {
                'type': 'str',
            },
            'scanners': {
                'type': 'str',
            },
            'dos_attacks': {
                'type': 'str',
            },
            'reputation': {
                'type': 'str',
            },
            'phishing': {
                'type': 'str',
            },
            'proxy': {
                'type': 'str',
            },
            'mobile_threats': {
                'type': 'str',
            },
            'tor_proxy': {
                'type': 'str',
            },
            'total_hits': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/threat-intel/threat-list/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


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
    url_base = "/axapi/v3/threat-intel/threat-list/{name}"

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
    if existing_config:
        for k, v in payload["threat-list"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["threat-list"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["threat-list"][k] = v
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
    payload = build_json("threat-list", module)
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

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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
