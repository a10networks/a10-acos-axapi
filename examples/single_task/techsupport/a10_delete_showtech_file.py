- name: Delete a10.acos_axapi.a10_Generates Show Tech file example playbook
  connection: local
  hosts: "{{desired_inventory_group}}"
  tasks:
  - name: Delete a10.acos_axapi.a10_Generates Show Tech file instance
    a10.acos_axapi.a10_generates_show_tech_file:
      state: absent
