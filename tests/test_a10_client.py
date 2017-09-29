from a10_ansible.a10_client import A10ClientBase

import mock
import unittest


class TestA10ClientBase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestA10ClientBase, self).__init__(*args, **kwargs)
        self.client_mock = mock.MagicMock()
        self.client_args = {"host": "10.10.10.10", "version": 2.1,
                            "username": "admin", "password": "a10", "port": 443}
        self.target = A10ClientBase(client=self.client_mock, **self.client_args)

    def test_authenticate(self):
        self.target._api.session.authenticate(self.client_args.get("username"),
                                              self.client_args.get("password"))

    def test_close(self):
        self.target._api.session.close()
