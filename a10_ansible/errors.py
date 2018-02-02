# Copyright 2014,  Doug Wiegley,  A10 Networks.
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


class ACOSException(Exception):
    def __init__(self, code=1, msg=''):
        self.code = code
        self.msg = msg
        super(ACOSException, self).__init__(msg)

    def __str__(self):
        return "%d %s" % (self.code, self.msg)


class ACOSUnsupportedVersion(ACOSException):
    pass


class ACOSUnknownError(ACOSException):
    pass


class AddressSpecifiedIsInUse(ACOSException):
    pass


class AuthenticationFailure(ACOSException):
    pass


class InvalidSessionID(ACOSException):
    pass


class Exists(ACOSException):
    pass


class NotFound(ACOSException):
    pass


class NoSuchServiceGroup(ACOSException):
    pass


class NotImplemented(ACOSException):
    pass


class InUse(ACOSException):
    pass


class InvalidPartitionParameter(ACOSException):
    pass


class MemoryFault(ACOSException):
    pass


class InvalidParameter(ACOSException):
    pass


class OutOfPartitions(ACOSException):
    pass


class PartitionIdExists(ACOSException):
    pass


class HMMissingHttpPassive(ACOSException):
    pass


class AxapiJsonFormatError(ACOSException):
    pass


class ConfigManagerNotReady(ACOSException):
    pass
