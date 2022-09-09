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

        # append required args we got from inventory file to module_args
        self._append_module_args(module_args, required_args)
        return self._execute_module(task_vars=task_vars, module_args=module_args)

    def _get_host_var(self, task_vars, name):
        """ function returns templated variable by parsing inventory_file for given host
        """
        return self._templar.template(
            task_vars.get(name),
            convert_bare=True,
            fail_on_undefined=True
          )

    def _get_required_params(self, task_vars):
        """ function returns required argument by parsing inventory_file for given host
        """
        ip = self._get_host_var(task_vars, "ansible_host")
        username = self._get_host_var(task_vars, "ansible_username")
        password = self._get_host_var(task_vars, "ansible_password")
        port = self._get_host_var(task_vars, "ansible_port")

        return ip, username, password, port

    def _append_module_args(self, old_mod_args, required_args):
        """ function appends required args we got from inventory file to module_args
        """
        ip, username, password, port = required_args
        old_mod_args['ansible_host'] = ip
        old_mod_args['ansible_username'] = username
        old_mod_args['ansible_password'] = password
        old_mod_args['ansible_port'] = port
