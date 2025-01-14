## Table of Contents
1. [Introduction](#Introduction)

2. [Support Matrix](#Support-Matrix)

3. [How it works](#How-it-works)

4. [How to install Ansbile on Ubuntu](#How-to-install-Ansbile-on-Ubuntu)

5. [How to install Ansbile on MacOS](#How-to-install-Ansbile-on-MacOS)

6. [How to install A10 Ansible modules](#How-to-install-A10-Ansible-modules)

7. [How to configure A10 Ansible modules](#How-to-A10-Ansible-modules)

8. [How to use A10 Ansible module collections](#How-to-use-A10-Ansible-module-collections)

9. [How to search Ansible module configurations](#How-to-search-Ansible-module-configurations)

10. [How to create new Ansible playbook example](#How-to-create-new-Ansible-playbook-example)

11. [How to execute Ansible playbooks from CLI](#How-to-execute-Ansible-playbooks-from-CLI)

12. [How to verify on Thunder](#How-to-verify-on-Thunder)

13. [How to change Thunder Password](#How-to-change-Thunder-Password)

14. [How to contribute](#How-to-contribute)

15. [Documentation](#Documentation)

16. [Test cases](#Test-cases)

17. [License](#License)

18. [Open Source Disclaimer](#Open-Source-Disclaimer)

19. [Report a issue](#Report-a-Issue)

20. [Support](#Support)

## Introduction

Thunder® ADCs (Application Delivery Controllers) are high-performance solutions to accelerate and optimize critical applications to ensure delivery and reliability.

A10 Ansible modules is a custom plugin to do configurations on Thunder. It includes example playbooks to apply on hardware and virtual appliances.

We only support Ansible version >=2.9

This code is now being generated using the SDK generator at https://github.com/a10networks/sdkgenerator

## Support Matrix

| ACOS Version | Ansible Version | GitHub Branch |
| :--------: | :-------: | :-------:  |
| `ACOS 6.0.6` | [6.0.6-11425](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=6.0.6-11425)  | [ACOS 6.0.6](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_606)  |
| `ACOS 6.0.5` | [6.0.5-91924](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=6.0.5-91924)  | [ACOS 6.0.5](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_605)  |
| `ACOS 6.0.4` | [6.0.4-90524](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=6.0.4-90524)  | [ACOS 6.0.4](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_604)  |
| `ACOS 6.0.3` | [6.0.3-11924](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=6.0.3-11924)  | [ACOS 6.0.3](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_603)  |
| `ACOS 6.0.2` | [6.0.2-110123](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=6.0.2-110123)  | [ACOS 6.0.2](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_602)  |
| `ACOS 6.0.1` | [6.0.1-71123](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=6.0.1-71123)  | [ACOS 6.0.1](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_601)  |
| `ACOS 6.0.0-p2` | [6.0.0-p2-050523](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=6.0.0-p2-050523)  | [ACOS 6.0.0-p2](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_600_p2)  |
| `ACOS 6.0.0-p1` |  [6.0.0-p1-033023](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=6.0.0-p1-033023)  | [ACOS 6.0.0-p1](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_600_p1) |
| `ACOS 5.2.1-p11` | [5.2.1-p11-90624](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=5.2.1-p11-90624)  | [ACOS 5.2.1-p11](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p11)  |
| `ACOS 5.2.1-p9` |  [5.2.1-p9-20224](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=5.2.1-p9-20224)  | [ACOS 5.2.1-p9](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p9)  |
| `ACOS 5.2.1-p8` |  [5.2.1-p8-102723](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=5.2.1-p8-102723)  | [ACOS 5.2.1-p8](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p8)  |
| `ACOS 5.2.1-p7` |  [5.2.1-p7-050523](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=5.2.1-p7-050523)  | [ACOS 5.2.1-p7](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p7) |
| `ACOS 5.2.1-p6` |  [5.2.1-p6-112522](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=5.2.1-p6-112522)  | [ACOS 5.2.1-p6](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p6) |
| `ACOS 5.2.1-p5`| [5.2.1-p5-100922](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=5.2.1-p5-100922)  | [ACOS 5.2.1-p5](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p5) |
| `ACOS 5.2.1-p4` | [5.2.1-p4-091922](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=5.2.1-p4-091922) | [ACOS 5.2.1-p4](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p4) |
| `ACOS 5.2.1-p3` | [1.2.10](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.10) | [ACOS 5.2.1-p3](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p3)  |
| `ACOS 5.2.1-p2` | [1.2.9](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.9) | [ACOS 5.2.1-p2](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p2)  |
| `ACOS 5.2.1-p1` | [1.2.8](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.8) | [ACOS 5.2.1-p1](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521_p1)  |
| `ACOS 5.2.1` | [1.2.7](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.7) | [ACOS 5.2.1](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_521)  |
| `ACOS 5.2.0-p1` | [1.2.6](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.6) | [ACOS 5.2.0-p1](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_520_p1)  |
| `ACOS 5.2.0` | [1.2.5](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.5) | [ACOS 5.2.0](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_520)  |
| `ACOS 5.1.0-p6` | [1.2.4](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.4) | [ACOS 5.1.0-p6](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_510_p6)  |
| `ACOS 5.1.0-p5` | [1.2.3](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.3) | [ACOS 5.1.0-p5](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_510_p5)  |
| `ACOS 5.1.0-p4` | [1.2.2](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.2) | [ACOS 5.1.0-p4](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_510_p4)  |
| `ACOS 5.1.0-p3` | [1.2.1](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.1) | [ACOS 5.1.0-p3](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_510_p3)  |
| `ACOS 5.1.0` | [1.2.0](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.2.0) | [ACOS 5.1.0](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_510)  |
| `ACOS 4.1.4-gr1-p9` | [1.1.2](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.1.2) | [ACOS 4.1.4-gr1-p9](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_414_gr1_p9) |
| `ACOS 4.1.4-gr1-p8` | [1.1.1](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.1.1) | [ACOS 4.1.4-gr1-p8](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_414_gr1_p8) |
| `ACOS 4.1.4-gr1-p7` | [1.1.0](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.1.0) | [ACOS 4.1.4-gr1-p7](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_414_gr1_p7) |
| `ACOS 4.1.4-gr1-p6` | [1.0.0](https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/?version=1.0.0) | [ACOS 4.1.4-gr1-p6](https://github.com/a10networks/a10-acos-axapi/tree/stable/acos_414_gr1_p6) |

For older versions, please visit https://galaxy.ansible.com/ui/repo/published/a10/acos_axapi/

## How it works
   1. Install Ansible on your local OS, Please refer below sections for more details.
   2. Search required Ansible configuration from examples. In case not found create a new one, Please refer below sections for more details.
   3. Execute Ansible playbooks to apply thunder configuration, Please refer below sections for more details.
   4. Verify thunder configuration after ansible playbook is applied, Please refer below sections for more details.

## How to install Ansbile on Ubuntu
To install Ansible on Ubuntu, Run the following command to download and install the latest version of Ansible:

```
apt install ansible
```

## How to install Ansbile on MacOS
To install Ansible on MacOS, Run the following command to download and install the latest version of Ansible:

```
brew install ansible
```

## How to install A10 Ansible modules
a10-acos-axapi is collection of custom ansible modules crated by a10Networks. It can be installed using following ways, it is assumed that ansible is already installed and configured.

### 1. Install from galaxy hub

`ansible-galaxy collection install a10.acos_axapi`

Be sure to note the collection path found within the output of the above command. For example:
```bash
$ ansible-galaxy collection install a10.acos_axapi
Process install dependency map
Starting collection install process
Installing 'a10.acos_axapi:1.0.0' to '/opt/.ansible/collections/ansible_collections/a10/acos_axapi'
```

In this example the collection directory path is: `/opt/.ansible/collections/ansible_collections/`

### 2. Install from the Github repository

  ~~~
  git clone https://github.com/a10networks/a10-acos-axapi
  cd a10-acos-axapi
  ansible-galaxy collection build
  ansible-galaxy collection install a10-acos_axapi*.tar.gz -p ./collections
  ~~~

## How to configure A10 Ansible Modules

#### 1. Set plugin path

Add below line in the `/etc/ansible/ansible.cfg` file

```bash
action_plugins  = <collection-dir-path>/a10/acos_axapi/plugins/action
```

#### 2. Alternative methods to set path

  1. Copy action plugin into one of the following
     - ~/.ansible/plugins
     - /usr/share/ansible/plugins folder

  2. Export following environment variables for new session

  ```bash
  export ANSIBLE_ACTION_PLUGINS=<collection-dir-path>/a10/acos_axapi/plugins/action
  ```

  3. Save this variable in .bashrc File

  ```bash
  export ANSIBLE_ACTION_PLUGINS=<collection-dir-path>/a10/acos_axapi/plugins/action
  ```



## How to use A10 Ansible module collections
Ansible collections are a powerful way to organize and distribute Ansible content, such as roles, modules, and plugins.

Action and module names are formatted based upon their API endpoint. For example, the virtual server endpoint is as follows: /axapi/v3/slb/virtual-server. As such, the action name is a10_slb_virtual_server and the module is a10_slb_virtual_server.py.

**Note that when getting information, changes made to the playbook will not result in a create, update or delete as the state has been put into no-op.

### Creating / updating a resource
Any of the following method can be used to create and run playbooks.

#### 1: Use the 'collections' keyword

```yaml
collections:
  - a10.acos_axapi

tasks:
  - module_name:
    - argument
  - module_name:
    - argument
```

#### 2: Use the Fully Qualified Collection Name (namespace.collection_name.module_name)

```yaml
tasks:
  - a10.acos_axapi.module_name:
    - argument
  - a10.acos_axapi.module_name:
    - argument
```

### Deleting a resource
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: absent</b>
</pre>

### Getting information about a single object
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: single</b>
</pre>

### Getting information about a collection
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: list</b>
</pre>
***NOTE*** - *When the ``` state ``` is noop and the ``` get_type ``` value is not specified, the playbook will automatically retrieve information for a single object, assuming ``` get_type ``` as ``` single ```. Please provide the required parameters to obtain details for a single object.*

### Getting operational information
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: oper</b>
</pre>

### Getting statistic information
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: stats</b>
</pre>

### Configuring a resource on a partition
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        <b>a10_partition: {{ partition_name }}</b>
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
</pre>

### Configuring a resource in a different device context
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        <b>a10_device_context_id: {{ device_context_id }}</b>
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
</pre>

### Uploading a file directly
*Note: Only available in modules with `file_path` argument*

<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        <b>file_path: "/path/to/file"</b>
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
</pre>

### Check Mode
Check mode can be specified in two ways:

<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>check_mode: yes</b>
</pre>

or

```bash
$ ansible-playbook -i <path_to_inventory> <playbook_name>.yml --check-mode
```


## How to search Ansible module configurations
To search for a Ansible Module Configuration in the existing examples, perform the following steps:

  1. Search the required Ansible Module configuration script directory navigate to examples > single_task directory.

     **Example:**

      If you want to apply the bgp router configuration on Thunder, search for the bgp directory under the single_task directory.

  2. Open the Ansible playbook from the directory.

     **Example:**

      Open a10_bgp_create.yaml playbook under the single_task directory.

  3. Update the **hosts** parameter in playbook and add, modify, or remove the Ansible module configuration parameters and their corresponding values as appropriate.

  ```
  - name: Create bgp example playbook
    connection: local
    hosts: "{{desired_inventory_group}}"
    tasks:
    - name: Create router bgp for acos
      a10.acos_axapi.a10_router_bgp:
        as_number: 106
  ```

  4. Save the playbook.

## How to create new Ansible playbook example

Here are step-by-step instructions for creating ansible playbook example.
For example if you want to apply bgp router configuration on thunder and which doesn't exist in examples.

1. Create a new directory to house your ansible playbook files.

```
  mkdir bgp
  cd bgp
```

2. Create a `.yaml` file, such as `a10_bgp_create.yaml`, in your "bgp" directory. In this file, define the ROUTER BGP configurations. Refer to the official documentation: https://documentation.a10networks.com/docs/IaC/Ansible/ansible/  for the required parameters.

  Here is basic example:

    - name: Create bgp example playbook
      connection: local
      hosts: "{{desired_inventory_group}}"        # Replace with your desired hosts
      tasks:
      - name: Create router bgp for acos
        a10.acos_axapi.a10_router_bgp:            # Replace with your desired module name
          as_number: 106                          # Replace with your desired bgp number

Adjust the BGP configuration parameters as needed.


## How to execute Ansible playbooks from CLI

### 1. With Inventory file
Sample Inventory file:

```shell
[vthunder]
<vthunder host_name/ip_address>

[vthunder:vars]
ansible_username=<username>
ansible_password=<password>
ansible_port=<port>
```

If you want to use an Inventory file to perform respective configurations through a playbook, you don't need to specify `ansible_host`, `ansible_username`, `ansible_password` and `ansible_port` in the playbook.

For example,
```
- name: <Description of playbook>
  connection: local
  hosts: <inventory_hostname>
  collections:
    <a10.acos_axapi>
  tasks:
    - name: <Description of task>
      <module_name>:
        <resource_key>: <resource_val>
        <another_resource_key>: <another_resource_val>
```

Use the following command to run playbook using an Inventory file parameters:
```shell
ansible-playbook -i <path_to_inventory> <name_of_playbook>
```

### 2. Without Inventory file
If you don't want to use Inventory file, then specify `ansible_host`, `ansible_username`, `ansible_password` and `ansible_port` arguments into playbook itself with hosts as `localhost`. And then the configurations will be performed on provided `ansible_host`.

For example,
```
- name: <Description of playbook>
  connection: local
  hosts: localhost
  collections:
    <a10.acos_axapi>
  tasks:
    - name: <Description of task>
      <module_name>:
        ansible_host: {{ ansible_host }}
        ansible_username: {{ ansible_username }}
        ansible_password: {{ ansible_password }}
        ansible_port: {{ ansible_port }}
        <resource_key>: <resource_val>
        <another_resource_key>: <another_resource_val>
```

Use the following command to run the playbook with local arguments:
```shell
ansible-playbook <name_of_playbook>
```

Use the following command to run the playbook:
```shell
ansible-playbook -i <path_to_inventory> <name_of_playbook>
```


## How to verify on Thunder

  To verify the applied configurations, follow below steps:

  1. SSH into the Thunder device using your username and password.
  2. Once connected, enter the following commands:

     1. `enable`

        ![image](https://github.com/smundhe-a10/terraform-provider-thunder/assets/107971633/7e532cee-fa8e-4af7-aa50-da56a24dd4c3)


     3. `show running-config`

        ![image](https://github.com/smundhe-a10/terraform-provider-thunder/assets/107971633/ae37e53d-c650-43f0-b71f-2416f4e5d65a)

## How to change Thunder Password
```
Please refer : /examples/single_task/admin/adminPassword/README.md
```

## How to contribute

If you have created a new example, please save the playbook file with a module-specific name, such as 'a10_bgp_create.yaml,' in a module name directory, like 'bgp'.

1. Clone the repository.
2. Copy the newly created playbook directory and place it under the /examples/single_task directory.
3. Create a MR against the master branch.

## Documentation

A10 Thunder AXAPI support documentation available at https://documentation.a10networks.com/docs/IaC/Ansible/ansible/

## Test Cases
Sample test cases added for the following configurations:
  - Bgp
  - Check Mode
  - Class List
  - Default Gateway
  - files
  - Gslb
  - Health
  - Network
  - Slb
  - Slb Template

### Run test cases
To test configurations on the acos using ansible playbooks goto ``` test ``` directory and use the following command:
```bash
sh run_test_playbooks.sh

```

## License
[APACHE LICENSE VERSION 2.0](LICENSE.txt)

All rights reserved @A10 Networks Inc.

## Open Source Disclaimer

	For more information, please refer [/OPEN-SOURCE-DISCLAIMER.pdf]
	For more open source licenses, please refer [/LICENSES]


## Report a Issue

Please raise issue in github repository. Please include the Ansible playbook or ansible module files that demonstrates the bug and the command output and stack traces will be helpful.

## Support
For all issues, please send an email to support@a10networks.com



