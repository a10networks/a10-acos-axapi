# a10-ansible
Repository of for ansible modules

This code is now being generated using the SDK generator at https://github.com/a10networks/sdkgenerator

## Summary
This repository is a set of Ansible modules and example playbooks for interacting with AXAPI v3 for configuration and monitoring of A10 ACOS-based hardware and virtual appliances. The module code and example playbooks are generated using a combination of Python code and Jinja templates.

## Installation
```bash
$ git clone https://github.com/a10networks/a10-ansible a10-ansible
$ cd a10-ansible 
$ chmod +x a10_install.sh
```

Check the ansible module location then run:

```
$ ./a10_install.sh
```

You can now delete the install files 

## Usage Information
All actions are required to have `a10_host`, `a10_username`, `a10_password`, `a10_port`, and `a10_protocol` specified. Note that `a10_host` refers to the ip address of the Thunder device.

Action and module names are formatted based upon their API endpoint. For example, the virtual server endpoint is as follows: `/axapi/v3/slb/virtual-server`. As such, the action name is `a10_slb_virtual_server` and the module is `a10_slb_virtual_server.py`. 

**Note that when getting information, changes made to the playbook will not result in a create or update as the state has been put into no-op.

### Creating / updating a resource
```
- name: <Description of playbook>
  connection: local
  hosts: <inventory>
  tasks:
    - name: <Description of task>
      <action>:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        <resource_key>: <resource_val>
        <another_resource_key>: <another_resource_val>
```

### Deleting a resource
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: absent</b>
</pre>

### Getting information about a single object
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: single</b> 
</pre>

### Getting information about a collection
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        state: noop
        get_type: list
</pre>

### Getting operational information
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        state: noop
        get_type: oper
</pre>

### Getting statistic information
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        state: noop
        get_type: stats
</pre>

### Check Mode
Check mode can be specified in two ways:

<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        check_mode: yes
</pre>

or

```bash
$ ansible-playbook <playbook_name>.yml --check-mode
```

## Examples
Please see (https://github.com/a10networks/a10-ansible/tree/master/examples) for example playbooks.

## Bug Reporting and Feature Requests
Please submit bug reports and feature requests via GitHub issues. When reporting bugs, please include the playbook that demonstrates the bug and the Ansible output. Stack traces are always nice, but playbooks work well. Please ensure any sensitive information is redacted as Issues and Pull Requests are publicly viewable.

## Contact
If you have a question that cannot be submitted via Github Issues, please email support@a10networks.com with "a10-ansible" in the subject line. 
