# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, A10 Networks Inc.
# GNU General Public License v3.0
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)
        module_args = self._task.args.copy()

        # get required arguments from inventory file for given hostname
        required_args = self._get_required_params(task_vars)

        # if inventory file does not contain all the required_args then run this module normally
        if None in required_args:
            return self._execute_module(task_vars=task_vars)

        # append required args we got from inventory file to module
        self._append_module_args(module_args, required_args)
        return self._execute_module(task_vars=task_vars, module_args=module_args)

    # function return required argument by parsing inventory_file for given host
    def _get_required_params(self, task_vars):
        ip = task_vars.get("ansible_host", None)
        username = task_vars.get("ansible_username", None)
        password = task_vars.get("ansible_password", None)
        port = task_vars.get("ansible_port", None)

        return ip, username, password, port

    def _append_module_args(self, old_mod_args, required_args):
        ip, username, password, port = required_args
        old_mod_args['ansible_host'] = ip
        old_mod_args['ansible_username'] = username
        old_mod_args['ansible_password'] = password
        old_mod_args['ansible_port'] = port
