#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_rule_set_tag
description:
    - Application Tag statistics in Rule Set
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
    rule_set_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            categorystat1:
                description:
                - "counter app category stat 1"
                type: str
            categorystat2:
                description:
                - "counter app category stat 2"
                type: str
            categorystat3:
                description:
                - "counter app category stat 3"
                type: str
            categorystat4:
                description:
                - "counter app category stat 4"
                type: str
            categorystat5:
                description:
                - "counter app category stat 5"
                type: str
            categorystat6:
                description:
                - "counter app category stat 6"
                type: str
            categorystat7:
                description:
                - "counter app category stat 7"
                type: str
            categorystat8:
                description:
                - "counter app category stat 8"
                type: str
            categorystat9:
                description:
                - "counter app category stat 9"
                type: str
            categorystat10:
                description:
                - "counter app category stat 10"
                type: str
            categorystat11:
                description:
                - "counter app category stat 11"
                type: str
            categorystat12:
                description:
                - "counter app category stat 12"
                type: str
            categorystat13:
                description:
                - "counter app category stat 13"
                type: str
            categorystat14:
                description:
                - "counter app category stat 14"
                type: str
            categorystat15:
                description:
                - "counter app category stat 15"
                type: str
            categorystat16:
                description:
                - "counter app category stat 16"
                type: str
            categorystat17:
                description:
                - "counter app category stat 17"
                type: str
            categorystat18:
                description:
                - "counter app category stat 18"
                type: str
            categorystat19:
                description:
                - "counter app category stat 19"
                type: str
            categorystat20:
                description:
                - "counter app category stat 20"
                type: str
            categorystat21:
                description:
                - "counter app category stat 21"
                type: str
            categorystat22:
                description:
                - "counter app category stat 22"
                type: str
            categorystat23:
                description:
                - "counter app category stat 23"
                type: str
            categorystat24:
                description:
                - "counter app category stat 24"
                type: str
            categorystat25:
                description:
                - "counter app category stat 25"
                type: str
            categorystat26:
                description:
                - "counter app category stat 26"
                type: str
            categorystat27:
                description:
                - "counter app category stat 27"
                type: str
            categorystat28:
                description:
                - "counter app category stat 28"
                type: str
            categorystat29:
                description:
                - "counter app category stat 29"
                type: str
            categorystat30:
                description:
                - "counter app category stat 30"
                type: str
            categorystat31:
                description:
                - "counter app category stat 31"
                type: str
            categorystat32:
                description:
                - "counter app category stat 32"
                type: str
            categorystat33:
                description:
                - "counter app category stat 33"
                type: str
            categorystat34:
                description:
                - "counter app category stat 34"
                type: str
            categorystat35:
                description:
                - "counter app category stat 35"
                type: str
            categorystat36:
                description:
                - "counter app category stat 36"
                type: str
            categorystat37:
                description:
                - "counter app category stat 37"
                type: str
            categorystat38:
                description:
                - "counter app category stat 38"
                type: str
            categorystat39:
                description:
                - "counter app category stat 39"
                type: str
            categorystat40:
                description:
                - "counter app category stat 40"
                type: str
            categorystat41:
                description:
                - "counter app category stat 41"
                type: str
            categorystat42:
                description:
                - "counter app category stat 42"
                type: str
            categorystat43:
                description:
                - "counter app category stat 43"
                type: str
            categorystat44:
                description:
                - "counter app category stat 44"
                type: str
            categorystat45:
                description:
                - "counter app category stat 45"
                type: str
            categorystat46:
                description:
                - "counter app category stat 46"
                type: str
            categorystat47:
                description:
                - "counter app category stat 47"
                type: str
            categorystat48:
                description:
                - "counter app category stat 48"
                type: str
            categorystat49:
                description:
                - "counter app category stat 49"
                type: str
            categorystat50:
                description:
                - "counter app category stat 50"
                type: str
            categorystat51:
                description:
                - "counter app category stat 51"
                type: str
            categorystat52:
                description:
                - "counter app category stat 52"
                type: str
            categorystat53:
                description:
                - "counter app category stat 53"
                type: str
            categorystat54:
                description:
                - "counter app category stat 54"
                type: str
            categorystat55:
                description:
                - "counter app category stat 55"
                type: str
            categorystat56:
                description:
                - "counter app category stat 56"
                type: str
            categorystat57:
                description:
                - "counter app category stat 57"
                type: str
            categorystat58:
                description:
                - "counter app category stat 58"
                type: str
            categorystat59:
                description:
                - "counter app category stat 59"
                type: str
            categorystat60:
                description:
                - "counter app category stat 60"
                type: str
            categorystat61:
                description:
                - "counter app category stat 61"
                type: str
            categorystat62:
                description:
                - "counter app category stat 62"
                type: str
            categorystat63:
                description:
                - "counter app category stat 63"
                type: str
            categorystat64:
                description:
                - "counter app category stat 64"
                type: str
            categorystat65:
                description:
                - "counter app category stat 65"
                type: str
            categorystat66:
                description:
                - "counter app category stat 66"
                type: str
            categorystat67:
                description:
                - "counter app category stat 67"
                type: str
            categorystat68:
                description:
                - "counter app category stat 68"
                type: str
            categorystat69:
                description:
                - "counter app category stat 69"
                type: str
            categorystat70:
                description:
                - "counter app category stat 70"
                type: str
            categorystat71:
                description:
                - "counter app category stat 71"
                type: str
            categorystat72:
                description:
                - "counter app category stat 72"
                type: str
            categorystat73:
                description:
                - "counter app category stat 73"
                type: str
            categorystat74:
                description:
                - "counter app category stat 74"
                type: str
            categorystat75:
                description:
                - "counter app category stat 75"
                type: str
            categorystat76:
                description:
                - "counter app category stat 76"
                type: str
            categorystat77:
                description:
                - "counter app category stat 77"
                type: str
            categorystat78:
                description:
                - "counter app category stat 78"
                type: str
            categorystat79:
                description:
                - "counter app category stat 79"
                type: str
            categorystat80:
                description:
                - "counter app category stat 80"
                type: str
            categorystat81:
                description:
                - "counter app category stat 81"
                type: str
            categorystat82:
                description:
                - "counter app category stat 82"
                type: str
            categorystat83:
                description:
                - "counter app category stat 83"
                type: str
            categorystat84:
                description:
                - "counter app category stat 84"
                type: str
            categorystat85:
                description:
                - "counter app category stat 85"
                type: str
            categorystat86:
                description:
                - "counter app category stat 86"
                type: str
            categorystat87:
                description:
                - "counter app category stat 87"
                type: str
            categorystat88:
                description:
                - "counter app category stat 88"
                type: str
            categorystat89:
                description:
                - "counter app category stat 89"
                type: str
            categorystat90:
                description:
                - "counter app category stat 90"
                type: str
            categorystat91:
                description:
                - "counter app category stat 91"
                type: str
            categorystat92:
                description:
                - "counter app category stat 92"
                type: str
            categorystat93:
                description:
                - "counter app category stat 93"
                type: str
            categorystat94:
                description:
                - "counter app category stat 94"
                type: str
            categorystat95:
                description:
                - "counter app category stat 95"
                type: str
            categorystat96:
                description:
                - "counter app category stat 96"
                type: str
            categorystat97:
                description:
                - "counter app category stat 97"
                type: str
            categorystat98:
                description:
                - "counter app category stat 98"
                type: str
            categorystat99:
                description:
                - "counter app category stat 99"
                type: str
            categorystat100:
                description:
                - "counter app category stat 100"
                type: str
            categorystat101:
                description:
                - "counter app category stat 101"
                type: str
            categorystat102:
                description:
                - "counter app category stat 102"
                type: str
            categorystat103:
                description:
                - "counter app category stat 103"
                type: str
            categorystat104:
                description:
                - "counter app category stat 104"
                type: str
            categorystat105:
                description:
                - "counter app category stat 105"
                type: str
            categorystat106:
                description:
                - "counter app category stat 106"
                type: str
            categorystat107:
                description:
                - "counter app category stat 107"
                type: str
            categorystat108:
                description:
                - "counter app category stat 108"
                type: str
            categorystat109:
                description:
                - "counter app category stat 109"
                type: str
            categorystat110:
                description:
                - "counter app category stat 110"
                type: str
            categorystat111:
                description:
                - "counter app category stat 111"
                type: str
            categorystat112:
                description:
                - "counter app category stat 112"
                type: str
            categorystat113:
                description:
                - "counter app category stat 113"
                type: str
            categorystat114:
                description:
                - "counter app category stat 114"
                type: str
            categorystat115:
                description:
                - "counter app category stat 115"
                type: str
            categorystat116:
                description:
                - "counter app category stat 116"
                type: str
            categorystat117:
                description:
                - "counter app category stat 117"
                type: str
            categorystat118:
                description:
                - "counter app category stat 118"
                type: str
            categorystat119:
                description:
                - "counter app category stat 119"
                type: str
            categorystat120:
                description:
                - "counter app category stat 120"
                type: str
            categorystat121:
                description:
                - "counter app category stat 121"
                type: str
            categorystat122:
                description:
                - "counter app category stat 122"
                type: str
            categorystat123:
                description:
                - "counter app category stat 123"
                type: str
            categorystat124:
                description:
                - "counter app category stat 124"
                type: str
            categorystat125:
                description:
                - "counter app category stat 125"
                type: str
            categorystat126:
                description:
                - "counter app category stat 126"
                type: str
            categorystat127:
                description:
                - "counter app category stat 127"
                type: str
            categorystat128:
                description:
                - "counter app category stat 128"
                type: str
            categorystat129:
                description:
                - "counter app category stat 129"
                type: str
            categorystat130:
                description:
                - "counter app category stat 130"
                type: str
            categorystat131:
                description:
                - "counter app category stat 131"
                type: str
            categorystat132:
                description:
                - "counter app category stat 132"
                type: str
            categorystat133:
                description:
                - "counter app category stat 133"
                type: str
            categorystat134:
                description:
                - "counter app category stat 134"
                type: str
            categorystat135:
                description:
                - "counter app category stat 135"
                type: str
            categorystat136:
                description:
                - "counter app category stat 136"
                type: str
            categorystat137:
                description:
                - "counter app category stat 137"
                type: str
            categorystat138:
                description:
                - "counter app category stat 138"
                type: str
            categorystat139:
                description:
                - "counter app category stat 139"
                type: str
            categorystat140:
                description:
                - "counter app category stat 140"
                type: str
            categorystat141:
                description:
                - "counter app category stat 141"
                type: str
            categorystat142:
                description:
                - "counter app category stat 142"
                type: str
            categorystat143:
                description:
                - "counter app category stat 143"
                type: str
            categorystat144:
                description:
                - "counter app category stat 144"
                type: str
            categorystat145:
                description:
                - "counter app category stat 145"
                type: str
            categorystat146:
                description:
                - "counter app category stat 146"
                type: str
            categorystat147:
                description:
                - "counter app category stat 147"
                type: str
            categorystat148:
                description:
                - "counter app category stat 148"
                type: str
            categorystat149:
                description:
                - "counter app category stat 149"
                type: str
            categorystat150:
                description:
                - "counter app category stat 150"
                type: str
            categorystat151:
                description:
                - "counter app category stat 151"
                type: str
            categorystat152:
                description:
                - "counter app category stat 152"
                type: str
            categorystat153:
                description:
                - "counter app category stat 153"
                type: str
            categorystat154:
                description:
                - "counter app category stat 154"
                type: str
            categorystat155:
                description:
                - "counter app category stat 155"
                type: str
            categorystat156:
                description:
                - "counter app category stat 156"
                type: str
            categorystat157:
                description:
                - "counter app category stat 157"
                type: str
            categorystat158:
                description:
                - "counter app category stat 158"
                type: str
            categorystat159:
                description:
                - "counter app category stat 159"
                type: str
            categorystat160:
                description:
                - "counter app category stat 160"
                type: str
            categorystat161:
                description:
                - "counter app category stat 161"
                type: str
            categorystat162:
                description:
                - "counter app category stat 162"
                type: str
            categorystat163:
                description:
                - "counter app category stat 163"
                type: str
            categorystat164:
                description:
                - "counter app category stat 164"
                type: str
            categorystat165:
                description:
                - "counter app category stat 165"
                type: str
            categorystat166:
                description:
                - "counter app category stat 166"
                type: str
            categorystat167:
                description:
                - "counter app category stat 167"
                type: str
            categorystat168:
                description:
                - "counter app category stat 168"
                type: str
            categorystat169:
                description:
                - "counter app category stat 169"
                type: str
            categorystat170:
                description:
                - "counter app category stat 170"
                type: str
            categorystat171:
                description:
                - "counter app category stat 171"
                type: str
            categorystat172:
                description:
                - "counter app category stat 172"
                type: str
            categorystat173:
                description:
                - "counter app category stat 173"
                type: str
            categorystat174:
                description:
                - "counter app category stat 174"
                type: str
            categorystat175:
                description:
                - "counter app category stat 175"
                type: str
            categorystat176:
                description:
                - "counter app category stat 176"
                type: str
            categorystat177:
                description:
                - "counter app category stat 177"
                type: str
            categorystat178:
                description:
                - "counter app category stat 178"
                type: str
            categorystat179:
                description:
                - "counter app category stat 179"
                type: str
            categorystat180:
                description:
                - "counter app category stat 180"
                type: str
            categorystat181:
                description:
                - "counter app category stat 181"
                type: str
            categorystat182:
                description:
                - "counter app category stat 182"
                type: str
            categorystat183:
                description:
                - "counter app category stat 183"
                type: str
            categorystat184:
                description:
                - "counter app category stat 184"
                type: str
            categorystat185:
                description:
                - "counter app category stat 185"
                type: str
            categorystat186:
                description:
                - "counter app category stat 186"
                type: str
            categorystat187:
                description:
                - "counter app category stat 187"
                type: str
            categorystat188:
                description:
                - "counter app category stat 188"
                type: str
            categorystat189:
                description:
                - "counter app category stat 189"
                type: str
            categorystat190:
                description:
                - "counter app category stat 190"
                type: str
            categorystat191:
                description:
                - "counter app category stat 191"
                type: str
            categorystat192:
                description:
                - "counter app category stat 192"
                type: str
            categorystat193:
                description:
                - "counter app category stat 193"
                type: str
            categorystat194:
                description:
                - "counter app category stat 194"
                type: str
            categorystat195:
                description:
                - "counter app category stat 195"
                type: str
            categorystat196:
                description:
                - "counter app category stat 196"
                type: str
            categorystat197:
                description:
                - "counter app category stat 197"
                type: str
            categorystat198:
                description:
                - "counter app category stat 198"
                type: str
            categorystat199:
                description:
                - "counter app category stat 199"
                type: str
            categorystat200:
                description:
                - "counter app category stat 200"
                type: str
            categorystat201:
                description:
                - "counter app category stat 201"
                type: str
            categorystat202:
                description:
                - "counter app category stat 202"
                type: str
            categorystat203:
                description:
                - "counter app category stat 203"
                type: str
            categorystat204:
                description:
                - "counter app category stat 204"
                type: str
            categorystat205:
                description:
                - "counter app category stat 205"
                type: str
            categorystat206:
                description:
                - "counter app category stat 206"
                type: str
            categorystat207:
                description:
                - "counter app category stat 207"
                type: str
            categorystat208:
                description:
                - "counter app category stat 208"
                type: str
            categorystat209:
                description:
                - "counter app category stat 209"
                type: str
            categorystat210:
                description:
                - "counter app category stat 210"
                type: str
            categorystat211:
                description:
                - "counter app category stat 211"
                type: str
            categorystat212:
                description:
                - "counter app category stat 212"
                type: str
            categorystat213:
                description:
                - "counter app category stat 213"
                type: str
            categorystat214:
                description:
                - "counter app category stat 214"
                type: str
            categorystat215:
                description:
                - "counter app category stat 215"
                type: str
            categorystat216:
                description:
                - "counter app category stat 216"
                type: str
            categorystat217:
                description:
                - "counter app category stat 217"
                type: str
            categorystat218:
                description:
                - "counter app category stat 218"
                type: str
            categorystat219:
                description:
                - "counter app category stat 219"
                type: str
            categorystat220:
                description:
                - "counter app category stat 220"
                type: str
            categorystat221:
                description:
                - "counter app category stat 221"
                type: str
            categorystat222:
                description:
                - "counter app category stat 222"
                type: str
            categorystat223:
                description:
                - "counter app category stat 223"
                type: str
            categorystat224:
                description:
                - "counter app category stat 224"
                type: str
            categorystat225:
                description:
                - "counter app category stat 225"
                type: str
            categorystat226:
                description:
                - "counter app category stat 226"
                type: str
            categorystat227:
                description:
                - "counter app category stat 227"
                type: str
            categorystat228:
                description:
                - "counter app category stat 228"
                type: str
            categorystat229:
                description:
                - "counter app category stat 229"
                type: str
            categorystat230:
                description:
                - "counter app category stat 230"
                type: str
            categorystat231:
                description:
                - "counter app category stat 231"
                type: str
            categorystat232:
                description:
                - "counter app category stat 232"
                type: str
            categorystat233:
                description:
                - "counter app category stat 233"
                type: str
            categorystat234:
                description:
                - "counter app category stat 234"
                type: str
            categorystat235:
                description:
                - "counter app category stat 235"
                type: str
            categorystat236:
                description:
                - "counter app category stat 236"
                type: str
            categorystat237:
                description:
                - "counter app category stat 237"
                type: str
            categorystat238:
                description:
                - "counter app category stat 238"
                type: str
            categorystat239:
                description:
                - "counter app category stat 239"
                type: str
            categorystat240:
                description:
                - "counter app category stat 240"
                type: str
            categorystat241:
                description:
                - "counter app category stat 241"
                type: str
            categorystat242:
                description:
                - "counter app category stat 242"
                type: str
            categorystat243:
                description:
                - "counter app category stat 243"
                type: str
            categorystat244:
                description:
                - "counter app category stat 244"
                type: str
            categorystat245:
                description:
                - "counter app category stat 245"
                type: str
            categorystat246:
                description:
                - "counter app category stat 246"
                type: str
            categorystat247:
                description:
                - "counter app category stat 247"
                type: str
            categorystat248:
                description:
                - "counter app category stat 248"
                type: str
            categorystat249:
                description:
                - "counter app category stat 249"
                type: str
            categorystat250:
                description:
                - "counter app category stat 250"
                type: str
            categorystat251:
                description:
                - "counter app category stat 251"
                type: str
            categorystat252:
                description:
                - "counter app category stat 252"
                type: str
            categorystat253:
                description:
                - "counter app category stat 253"
                type: str
            categorystat254:
                description:
                - "counter app category stat 254"
                type: str
            categorystat255:
                description:
                - "counter app category stat 255"
                type: str
            categorystat256:
                description:
                - "counter app category stat 255"
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
    "stats",
    "uuid",
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
        'uuid': {
            'type': 'str',
        },
        'stats': {
            'type': 'dict',
            'categorystat1': {
                'type': 'str',
            },
            'categorystat2': {
                'type': 'str',
            },
            'categorystat3': {
                'type': 'str',
            },
            'categorystat4': {
                'type': 'str',
            },
            'categorystat5': {
                'type': 'str',
            },
            'categorystat6': {
                'type': 'str',
            },
            'categorystat7': {
                'type': 'str',
            },
            'categorystat8': {
                'type': 'str',
            },
            'categorystat9': {
                'type': 'str',
            },
            'categorystat10': {
                'type': 'str',
            },
            'categorystat11': {
                'type': 'str',
            },
            'categorystat12': {
                'type': 'str',
            },
            'categorystat13': {
                'type': 'str',
            },
            'categorystat14': {
                'type': 'str',
            },
            'categorystat15': {
                'type': 'str',
            },
            'categorystat16': {
                'type': 'str',
            },
            'categorystat17': {
                'type': 'str',
            },
            'categorystat18': {
                'type': 'str',
            },
            'categorystat19': {
                'type': 'str',
            },
            'categorystat20': {
                'type': 'str',
            },
            'categorystat21': {
                'type': 'str',
            },
            'categorystat22': {
                'type': 'str',
            },
            'categorystat23': {
                'type': 'str',
            },
            'categorystat24': {
                'type': 'str',
            },
            'categorystat25': {
                'type': 'str',
            },
            'categorystat26': {
                'type': 'str',
            },
            'categorystat27': {
                'type': 'str',
            },
            'categorystat28': {
                'type': 'str',
            },
            'categorystat29': {
                'type': 'str',
            },
            'categorystat30': {
                'type': 'str',
            },
            'categorystat31': {
                'type': 'str',
            },
            'categorystat32': {
                'type': 'str',
            },
            'categorystat33': {
                'type': 'str',
            },
            'categorystat34': {
                'type': 'str',
            },
            'categorystat35': {
                'type': 'str',
            },
            'categorystat36': {
                'type': 'str',
            },
            'categorystat37': {
                'type': 'str',
            },
            'categorystat38': {
                'type': 'str',
            },
            'categorystat39': {
                'type': 'str',
            },
            'categorystat40': {
                'type': 'str',
            },
            'categorystat41': {
                'type': 'str',
            },
            'categorystat42': {
                'type': 'str',
            },
            'categorystat43': {
                'type': 'str',
            },
            'categorystat44': {
                'type': 'str',
            },
            'categorystat45': {
                'type': 'str',
            },
            'categorystat46': {
                'type': 'str',
            },
            'categorystat47': {
                'type': 'str',
            },
            'categorystat48': {
                'type': 'str',
            },
            'categorystat49': {
                'type': 'str',
            },
            'categorystat50': {
                'type': 'str',
            },
            'categorystat51': {
                'type': 'str',
            },
            'categorystat52': {
                'type': 'str',
            },
            'categorystat53': {
                'type': 'str',
            },
            'categorystat54': {
                'type': 'str',
            },
            'categorystat55': {
                'type': 'str',
            },
            'categorystat56': {
                'type': 'str',
            },
            'categorystat57': {
                'type': 'str',
            },
            'categorystat58': {
                'type': 'str',
            },
            'categorystat59': {
                'type': 'str',
            },
            'categorystat60': {
                'type': 'str',
            },
            'categorystat61': {
                'type': 'str',
            },
            'categorystat62': {
                'type': 'str',
            },
            'categorystat63': {
                'type': 'str',
            },
            'categorystat64': {
                'type': 'str',
            },
            'categorystat65': {
                'type': 'str',
            },
            'categorystat66': {
                'type': 'str',
            },
            'categorystat67': {
                'type': 'str',
            },
            'categorystat68': {
                'type': 'str',
            },
            'categorystat69': {
                'type': 'str',
            },
            'categorystat70': {
                'type': 'str',
            },
            'categorystat71': {
                'type': 'str',
            },
            'categorystat72': {
                'type': 'str',
            },
            'categorystat73': {
                'type': 'str',
            },
            'categorystat74': {
                'type': 'str',
            },
            'categorystat75': {
                'type': 'str',
            },
            'categorystat76': {
                'type': 'str',
            },
            'categorystat77': {
                'type': 'str',
            },
            'categorystat78': {
                'type': 'str',
            },
            'categorystat79': {
                'type': 'str',
            },
            'categorystat80': {
                'type': 'str',
            },
            'categorystat81': {
                'type': 'str',
            },
            'categorystat82': {
                'type': 'str',
            },
            'categorystat83': {
                'type': 'str',
            },
            'categorystat84': {
                'type': 'str',
            },
            'categorystat85': {
                'type': 'str',
            },
            'categorystat86': {
                'type': 'str',
            },
            'categorystat87': {
                'type': 'str',
            },
            'categorystat88': {
                'type': 'str',
            },
            'categorystat89': {
                'type': 'str',
            },
            'categorystat90': {
                'type': 'str',
            },
            'categorystat91': {
                'type': 'str',
            },
            'categorystat92': {
                'type': 'str',
            },
            'categorystat93': {
                'type': 'str',
            },
            'categorystat94': {
                'type': 'str',
            },
            'categorystat95': {
                'type': 'str',
            },
            'categorystat96': {
                'type': 'str',
            },
            'categorystat97': {
                'type': 'str',
            },
            'categorystat98': {
                'type': 'str',
            },
            'categorystat99': {
                'type': 'str',
            },
            'categorystat100': {
                'type': 'str',
            },
            'categorystat101': {
                'type': 'str',
            },
            'categorystat102': {
                'type': 'str',
            },
            'categorystat103': {
                'type': 'str',
            },
            'categorystat104': {
                'type': 'str',
            },
            'categorystat105': {
                'type': 'str',
            },
            'categorystat106': {
                'type': 'str',
            },
            'categorystat107': {
                'type': 'str',
            },
            'categorystat108': {
                'type': 'str',
            },
            'categorystat109': {
                'type': 'str',
            },
            'categorystat110': {
                'type': 'str',
            },
            'categorystat111': {
                'type': 'str',
            },
            'categorystat112': {
                'type': 'str',
            },
            'categorystat113': {
                'type': 'str',
            },
            'categorystat114': {
                'type': 'str',
            },
            'categorystat115': {
                'type': 'str',
            },
            'categorystat116': {
                'type': 'str',
            },
            'categorystat117': {
                'type': 'str',
            },
            'categorystat118': {
                'type': 'str',
            },
            'categorystat119': {
                'type': 'str',
            },
            'categorystat120': {
                'type': 'str',
            },
            'categorystat121': {
                'type': 'str',
            },
            'categorystat122': {
                'type': 'str',
            },
            'categorystat123': {
                'type': 'str',
            },
            'categorystat124': {
                'type': 'str',
            },
            'categorystat125': {
                'type': 'str',
            },
            'categorystat126': {
                'type': 'str',
            },
            'categorystat127': {
                'type': 'str',
            },
            'categorystat128': {
                'type': 'str',
            },
            'categorystat129': {
                'type': 'str',
            },
            'categorystat130': {
                'type': 'str',
            },
            'categorystat131': {
                'type': 'str',
            },
            'categorystat132': {
                'type': 'str',
            },
            'categorystat133': {
                'type': 'str',
            },
            'categorystat134': {
                'type': 'str',
            },
            'categorystat135': {
                'type': 'str',
            },
            'categorystat136': {
                'type': 'str',
            },
            'categorystat137': {
                'type': 'str',
            },
            'categorystat138': {
                'type': 'str',
            },
            'categorystat139': {
                'type': 'str',
            },
            'categorystat140': {
                'type': 'str',
            },
            'categorystat141': {
                'type': 'str',
            },
            'categorystat142': {
                'type': 'str',
            },
            'categorystat143': {
                'type': 'str',
            },
            'categorystat144': {
                'type': 'str',
            },
            'categorystat145': {
                'type': 'str',
            },
            'categorystat146': {
                'type': 'str',
            },
            'categorystat147': {
                'type': 'str',
            },
            'categorystat148': {
                'type': 'str',
            },
            'categorystat149': {
                'type': 'str',
            },
            'categorystat150': {
                'type': 'str',
            },
            'categorystat151': {
                'type': 'str',
            },
            'categorystat152': {
                'type': 'str',
            },
            'categorystat153': {
                'type': 'str',
            },
            'categorystat154': {
                'type': 'str',
            },
            'categorystat155': {
                'type': 'str',
            },
            'categorystat156': {
                'type': 'str',
            },
            'categorystat157': {
                'type': 'str',
            },
            'categorystat158': {
                'type': 'str',
            },
            'categorystat159': {
                'type': 'str',
            },
            'categorystat160': {
                'type': 'str',
            },
            'categorystat161': {
                'type': 'str',
            },
            'categorystat162': {
                'type': 'str',
            },
            'categorystat163': {
                'type': 'str',
            },
            'categorystat164': {
                'type': 'str',
            },
            'categorystat165': {
                'type': 'str',
            },
            'categorystat166': {
                'type': 'str',
            },
            'categorystat167': {
                'type': 'str',
            },
            'categorystat168': {
                'type': 'str',
            },
            'categorystat169': {
                'type': 'str',
            },
            'categorystat170': {
                'type': 'str',
            },
            'categorystat171': {
                'type': 'str',
            },
            'categorystat172': {
                'type': 'str',
            },
            'categorystat173': {
                'type': 'str',
            },
            'categorystat174': {
                'type': 'str',
            },
            'categorystat175': {
                'type': 'str',
            },
            'categorystat176': {
                'type': 'str',
            },
            'categorystat177': {
                'type': 'str',
            },
            'categorystat178': {
                'type': 'str',
            },
            'categorystat179': {
                'type': 'str',
            },
            'categorystat180': {
                'type': 'str',
            },
            'categorystat181': {
                'type': 'str',
            },
            'categorystat182': {
                'type': 'str',
            },
            'categorystat183': {
                'type': 'str',
            },
            'categorystat184': {
                'type': 'str',
            },
            'categorystat185': {
                'type': 'str',
            },
            'categorystat186': {
                'type': 'str',
            },
            'categorystat187': {
                'type': 'str',
            },
            'categorystat188': {
                'type': 'str',
            },
            'categorystat189': {
                'type': 'str',
            },
            'categorystat190': {
                'type': 'str',
            },
            'categorystat191': {
                'type': 'str',
            },
            'categorystat192': {
                'type': 'str',
            },
            'categorystat193': {
                'type': 'str',
            },
            'categorystat194': {
                'type': 'str',
            },
            'categorystat195': {
                'type': 'str',
            },
            'categorystat196': {
                'type': 'str',
            },
            'categorystat197': {
                'type': 'str',
            },
            'categorystat198': {
                'type': 'str',
            },
            'categorystat199': {
                'type': 'str',
            },
            'categorystat200': {
                'type': 'str',
            },
            'categorystat201': {
                'type': 'str',
            },
            'categorystat202': {
                'type': 'str',
            },
            'categorystat203': {
                'type': 'str',
            },
            'categorystat204': {
                'type': 'str',
            },
            'categorystat205': {
                'type': 'str',
            },
            'categorystat206': {
                'type': 'str',
            },
            'categorystat207': {
                'type': 'str',
            },
            'categorystat208': {
                'type': 'str',
            },
            'categorystat209': {
                'type': 'str',
            },
            'categorystat210': {
                'type': 'str',
            },
            'categorystat211': {
                'type': 'str',
            },
            'categorystat212': {
                'type': 'str',
            },
            'categorystat213': {
                'type': 'str',
            },
            'categorystat214': {
                'type': 'str',
            },
            'categorystat215': {
                'type': 'str',
            },
            'categorystat216': {
                'type': 'str',
            },
            'categorystat217': {
                'type': 'str',
            },
            'categorystat218': {
                'type': 'str',
            },
            'categorystat219': {
                'type': 'str',
            },
            'categorystat220': {
                'type': 'str',
            },
            'categorystat221': {
                'type': 'str',
            },
            'categorystat222': {
                'type': 'str',
            },
            'categorystat223': {
                'type': 'str',
            },
            'categorystat224': {
                'type': 'str',
            },
            'categorystat225': {
                'type': 'str',
            },
            'categorystat226': {
                'type': 'str',
            },
            'categorystat227': {
                'type': 'str',
            },
            'categorystat228': {
                'type': 'str',
            },
            'categorystat229': {
                'type': 'str',
            },
            'categorystat230': {
                'type': 'str',
            },
            'categorystat231': {
                'type': 'str',
            },
            'categorystat232': {
                'type': 'str',
            },
            'categorystat233': {
                'type': 'str',
            },
            'categorystat234': {
                'type': 'str',
            },
            'categorystat235': {
                'type': 'str',
            },
            'categorystat236': {
                'type': 'str',
            },
            'categorystat237': {
                'type': 'str',
            },
            'categorystat238': {
                'type': 'str',
            },
            'categorystat239': {
                'type': 'str',
            },
            'categorystat240': {
                'type': 'str',
            },
            'categorystat241': {
                'type': 'str',
            },
            'categorystat242': {
                'type': 'str',
            },
            'categorystat243': {
                'type': 'str',
            },
            'categorystat244': {
                'type': 'str',
            },
            'categorystat245': {
                'type': 'str',
            },
            'categorystat246': {
                'type': 'str',
            },
            'categorystat247': {
                'type': 'str',
            },
            'categorystat248': {
                'type': 'str',
            },
            'categorystat249': {
                'type': 'str',
            },
            'categorystat250': {
                'type': 'str',
            },
            'categorystat251': {
                'type': 'str',
            },
            'categorystat252': {
                'type': 'str',
            },
            'categorystat253': {
                'type': 'str',
            },
            'categorystat254': {
                'type': 'str',
            },
            'categorystat255': {
                'type': 'str',
            },
            'categorystat256': {
                'type': 'str',
            }
        }
    })
    # Parent keys
    rv.update(dict(rule_set_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{rule_set_name}/tag"

    f_dict = {}
    f_dict["rule_set_name"] = module.params["rule_set_name"]

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
    url_base = "/axapi/v3/rule-set/{rule_set_name}/tag"

    f_dict = {}
    f_dict["rule_set_name"] = module.params["rule_set_name"]

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


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


def create(module, result):
    try:
        post_result = module.client.post(new_url(module))
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config):
    try:
        post_result = module.client.post(existing_url(module))
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
    if module.check_mode:
        return report_changes(module, result, existing_config)
    if not existing_config:
        return create(module, result)
    else:
        return update(module, result, existing_config)


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
