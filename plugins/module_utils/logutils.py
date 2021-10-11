# Copyright 2021, All Rights Reserved,  A10 Networks.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import six

CLEAN_FIELDS = ["username", "password"]

REPLACEMENT = "*" * 8


def clean(data, field=None):
    if field in CLEAN_FIELDS:
        return REPLACEMENT

    # Mocks are gross and they don't live in production code.
    # We can ignore them.
    if type(data).__module__ == 'mock.mock':
        return data

    if type(data) is dict:
        return type(data)(
            (x, clean(y, field=x)) for x, y in six.iteritems(data)
        )
    elif isinstance(data, six.string_types):
        return data
    elif isinstance(data, (list, tuple)):
        return type(data)(clean(x) for x in data)