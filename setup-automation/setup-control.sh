#!/bin/bash

systemctl stop systemd-tmpfiles-setup.service
systemctl disable systemd-tmpfiles-setup.service

nmcli connection add type ethernet con-name enp2s0 ifname enp2s0 ipv4.addresses 192.168.1.10/24 ipv4.method manual connection.autoconnect yes
nmcli connection up enp2s0
echo "192.168.1.10 control.lab control" >> /etc/hosts



RHEL_SSH_DIR="/home/rhel/.ssh"
RHEL_PRIVATE_KEY="$RHEL_SSH_DIR/id_rsa"
RHEL_PUBLIC_KEY="$RHEL_SSH_DIR/id_rsa.pub"

if [ -f "$RHEL_PRIVATE_KEY" ]; then
    echo "SSH key already exists for rhel user: $RHEL_PRIVATE_KEY"
else
    echo "Creating SSH key for rhel user..."
    sudo -u rhel mkdir -p /home/rhel/.ssh
    sudo -u rhel chmod 700 /home/rhel/.ssh
    sudo -u rhel ssh-keygen -t rsa -b 4096 -C "rhel@$(hostname)" -f /home/rhel/.ssh/id_rsa -N "" -q
    sudo -u rhel chmod 600 /home/rhel/.ssh/id_rsa*
    
    if [ -f "$RHEL_PRIVATE_KEY" ]; then
        echo "SSH key created successfully for rhel user"
    else
        echo "Error: Failed to create SSH key for rhel user"
    fi
fi

# Pre-configure Cockpit for route access
# This allows Cockpit to accept connections from the OpenShift route
# The Lightspeed-generated playbook will install Cockpit, which will use this config
echo "Pre-configuring Cockpit for route access..."
mkdir -p /etc/cockpit
cat > /etc/cockpit/cockpit.conf << COCKPIT_EOF
[WebService]
Origins = https://cockpit-${GUID}.${DOMAIN}
AllowUnencrypted = true
COCKPIT_EOF
echo "Cockpit configuration created at /etc/cockpit/cockpit.conf"

# Create a playbook for the user to execute

tee /tmp/setup.yml << EOF
### Automation Controller setup 
###
---
- name: Setup Controller
  hosts: localhost
  connection: local
  collections:
    - ansible.controller

  vars:
    aws_access_key: "{{ lookup('env', 'AWS_ACCESS_KEY_ID') | default('AWS_ACCESS_KEY_ID_NOT_FOUND', true) }}"
    aws_secret_key: "{{ lookup('env', 'AWS_SECRET_ACCESS_KEY') | default('AWS_SECRET_ACCESS_KEY_NOT_FOUND', true) }}"
    aws_default_region: "{{ lookup('env', 'AWS_DEFAULT_REGION') | default('AWS_DEFAULT_REGION_NOT_FOUND', true) }}"
    quay_username: "{{ lookup('env', 'QUAY_USERNAME') | default('QUAY_USERNAME_NOT_FOUND', true) }}"
    quay_password: "{{ lookup('env', 'QUAY_PASSWORD') | default('QUAY_PASSWORD_NOT_FOUND', true) }}"
    azure_subscription: "{{ lookup('env', 'AZURE_SUBSCRIPTION') | default('AZURE_SUBSCRIPTION_NOT_FOUND', true) }}"
    azure_tenant: "{{ lookup('env', 'AZURE_TENANT') | default('AZURE_TENANT_NOT_FOUND', true) }}"
    azure_client_id: "{{ lookup('env', 'AZURE_CLIENT_ID') | default('AZURE_CLIENT_ID_NOT_FOUND', true) }}"
    azure_password: "{{ lookup('env', 'AZURE_PASSWORD') | default('AZURE_PASSWORD_NOT_FOUND', true) }}"
    azure_resourcegroup: "{{ lookup('env', 'AZURE_RESOURCEGROUP') | default('AZURE_RESOURCEGROUP_NOT_FOUND', true) }}"

  vars_files:
    - track_vars.yml
    - vault_track_vars.yml

  vars:
      controller_login: &controller_login
      controller_username: "{{ controller_username }}"
      controller_password: "{{ controller_password }}"
      controller_host: "{{ controller_hostname }}"
      validate_certs: "{{ controller_validate_certs }}"

  tasks:
 
  # Have to update objects with $_SANDBOX_ID in FQDN.
    - name: Setup initial environment
      tags:
        - setup-env
      block:
    #  Needs Instruqt Azure account name to be "azureadmin"
        - name: Setup Azure environment vars
          ansible.builtin.blockinfile:
            path: /etc/profile
            mode: "0644"
            owner: root
            group: root
            block: |
              export AZURE_CLIENT_ID="${INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_SPN_ID}"
              export AZURE_TENANT="${INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_TENANT_ID}"
              export AZURE_SUBSCRIPTION_ID="${INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_SUBSCRIPTION_ID}"
              export AZURE_SECRET="${INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_SPN_PASSWORD}"
              export AZURE_PASSWORD="${INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_PASSWORD}"
              export AZURE_AD_USER="${INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_USERNAME}"

        - name: Wait for controller availability
          ansible.builtin.uri:
            url: https://localhost/api/v2/ping/
            method: GET
            user: "{{ controller_login.controller_username }}"
            password: "{{ controller_login.controller_password }}"
            validate_certs: "{{ controller_login.validate_certs }}"
          register: __controller_check
          until: 
            - __controller_check.json is defined 
            - __controller_check.json.instances[0].capacity > 0
            - __controller_check.json.instance_groups[0].capacity > 0
          retries: 20
          delay: 1

        #  Temp
        - name: Remove current repo dir
          ansible.builtin.file:
            state: absent
            path: "~{{ student_username }}/acme_corp"
          become_user: "{{ student_username }}"

        # # temp
        - name: Clone repository to {{ student_username }} # noqa latest[git]
          environment:
            GIT_SSL_NO_VERIFY: true
          ansible.builtin.git:
            repo: "{{ gitea_app_url }}/{{ student_username }}/{{ gitea_repo_name }}"
            dest: "~{{ student_username }}/acme_corp"
          become_user: "{{ student_username }}"

        # temp or rh1 branch
        - name: Temp - checkout devel
          ansible.builtin.command:
            # TODO fix to correct branch
            cmd: git checkout devel
            chdir: "~{{ student_username }}/{{ gitea_repo_name }}"
          become_user: "{{ student_username }}"
        # temp
        - name: Copy VS Code workspace settings to repo
          ansible.builtin.copy:
            src: "/opt/setup-scripts/{{ track_slug }}/files/.vscode"
            dest: "~{{ student_username }}/{{ gitea_repo_name }}/"
            remote_src: true
            owner: "{{ student_username }}"
            group: "{{ student_username }}"
            directory_mode: "755"
            mode: "644"
        # # temp
        - name: Fix directory permissions - {{ gitea_repo_name }}
          ansible.builtin.file:
            path: "~{{ student_username }}/{{ gitea_repo_name }}/.vscode"
            state: directory
            owner: "{{ student_username }}"
            group: "{{ student_username }}"
            mode: "755"
  
    - name: Solve Overwrite demo Playbooks with solution playbooks - {{ gitea_repo_name }}
      ansible.builtin.copy:
        src: "{{ item.source_playbook }}"
        dest: "{{ item.dest_playbook }}"
        owner: "{{ student_username }}"
        group: "{{ student_username }}"
        remote_src: "{{ item.remote_src | default(omit) }}"
        mode: "644"
      loop: "{{ lookup('ansible.builtin.vars', content_list)['playbooks'] }}"
      tags:
        - setup-workflow-playbooks
        - solve-workflow-playbooks
        - solve-database-playbooks
        - solve-monitoring-playbooks
        - solve-aws-playbooks
        - solve-azure-playbooks
        - setup-playground-playbooks

    - name: Setup and Solve - Git add Playbooks to repo
      ansible.builtin.command:
        cmd: "git add {{ item.dest_playbook }}"
        chdir: "~{{ student_username }}/{{ gitea_repo_name }}"
      become_user: "{{ student_username }}"
      register: __add_output
      changed_when: __add_output.rc == 0
      loop: "{{ lookup('ansible.builtin.vars', content_list)['playbooks']  }}"
      tags:
        - setup-playground-playbooks
        - setup-workflow-playbooks
        - solve-monitoring-playbooks
        - solve-database-playbooks
        - solve-aws-playbooks
        - solve-azure-playbooks
        - solve-workflow-playbooks

    - name: Setup - Push challenge setup commit to repo
      ansible.builtin.command:
        cmd: "{{ item }}"
        chdir: "~{{ student_username }}/{{ gitea_repo_name }}"
      become_user: "{{ student_username }}"
      register: __output
      failed_when: false # TODO loop with matching changed_when and failed_when text.
      loop:
        - "git commit -m'Challenge setup commit.'"
        - "git push -u origin devel --force" # Temp
        # - "git push -u origin main --force"
      tags:
        - setup-playground-playbooks
        - setup-workflow-playbooks
        - solve-workflow-playbooks
        - solve-database-playbooks
        - solve-monitoring-playbooks
        - solve-aws-playbooks
        - solve-azure-playbooks

    - name: Update controller credentials - {{ content_list }}
      awx.awx.credential:
        name: "{{ item.name }}"
        description: "{{ item.description }}"
        organization: "{{ item.organization }}"
        state: "{{ item.state }}"
        inputs: "{{ item.inputs }}"
        credential_type: "{{ item.credential_type }}"
        <<: *controller_login
      # no_log: true
      delegate_to: localhost
      loop: "{{ controller_credentials[content_list] }}"
      when: 
        - controller_credentials is defined
        - content_list is defined
      retries: 10
      delay: 1
      tags:
        # Have to add playground-credentials because of content_list var
        - setup-playground-credentials
        - setup-aws-credentials
        - setup-azure-credentials

    - name: Setup - create job templates - {{ content_list }}
      awx.awx.job_template:
        name: "{{ item.name }}"
        state: "{{ item.state }}"
        become_enabled: "{{ item.become_enabled | default(omit)}}"
        project: "{{ item.project }}"
        credentials: "{{ item.credentials }}"
        organization: "{{ item.organization }}"
        inventory: "{{ item.inventory }}"
        playbook: "{{ item.playbook }}"
        survey_spec: "{{ item.survey_spec | default(omit) }}"
        ask_inventory_on_launch: "{{ item.ask_inventory_on_launch | default(false) }}"
        ask_limit_on_launch: "{{ item.ask_limit_on_launch | default(omit) }}"
        extra_vars: "{{ item.extra_vars | default(omit) }}"
        limit: "{{ item.limit | default(omit) }}"
        execution_environment: "{{ item.execution_environment }}"
        job_tags: "{{ item.job_tags | default(omit) }}"
        <<: *controller_login
      delegate_to: localhost
      register: __create_job_templates
      until: not __create_job_templates.failed
      retries: 20
      delay: 1
      loop: "{{ controller_templates[content_list] }}"
      when: 
        - controller_templates[content_list] is defined
      tags:
        - setup-monitoring-jt
        - setup-database-jt
        - setup-workflow-jt
        - setup-aws-jt
        - setup-azure-jt
        - setup-playground-jt

    - name: Setup AWS resources
      delegate_to: localhost
      tags:
        - setup-aws-resources
      block:
        - name: Create keypair called lightspeed-keypair from instruqt_lab.pub key
          amazon.aws.ec2_key:
            name: lightspeed-keypair
            key_material: "{{ lookup('ansible.builtin.file', '~/.ssh/instruqt_lab.pub') }}"
            tags:
              function: lightspeed-demo

        - name: Create VPC named vpc-lightspeed
          amazon.aws.ec2_vpc_net:
            name: vpc-lightspeed
            cidr_block: 10.0.0.0/16
            tags:
              Name: vpc-lightspeed
              function: lightspeed-demo
            state: present
          register: ec2_vpc_net

        - name: Create vpc_id var
          ansible.builtin.set_fact:
            vpc_id: "{{ ec2_vpc_net.vpc.id }}"

        - name: Create security group named secgroup-lightspeed in vpc-lightspeed vpc
          amazon.aws.ec2_security_group:
            name: secgroup-lightspeed
            description: SSH access
            vpc_id: "{{ vpc_id }}"
            state: present
            rules:
              - proto: tcp
                ports:
                  - 22
                cidr_ip: 0.0.0.0/0
                rule_desc: allow all on ssh port
            tags:
              function: lightspeed-demo
          register: secgroup_lightspeed

        - name: Create subnet with 10.0.1.0/24 cidr called subnet-lightspeed
          amazon.aws.ec2_vpc_subnet:
            vpc_id: "{{ vpc_id }}"
            cidr: 10.0.1.0/24
            az: us-east-1a
            state: present
            tags:
              Name: subnet-lightspeed
          register: subnet_lightspeed

        - name: Create internet gateway
          amazon.aws.ec2_vpc_igw:
            vpc_id: "{{ vpc_id }}"
            tags:
              Name: gateway-lightspeed
            state: present
          register: igw

        - name: Create public route table
          amazon.aws.ec2_vpc_route_table:
            vpc_id: "{{ vpc_id }}"
            subnets:
              - "{{ subnet_lightspeed.subnet.id }}"
            routes:
              - dest: 0.0.0.0/0
                gateway_id: "{{ igw.gateway_id }}"

    - name: Setup Azure resources
      delegate_to: localhost
      tags:
        - setup-azure-resources
      block:
        - name: Create files folder
          ansible.builtin.file:
            path: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/cloud/azure/files"
            state: directory
            owner: "{{ student_username }}"
            group: "{{ student_username }}"
            mode: '0755'
          delegate_to: controller.acme.example.com

        - name: Copy Instruqt lab SSH keys
          ansible.builtin.copy:
            src: "~/.ssh/{{ item.name }}"
            dest: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/cloud/azure/files/azure_demo_ssh_key{{ item.name | splitext | last }}"
            owner: "{{ student_username }}"
            group: "{{ student_username }}"
            mode: "{{ item.mode }}"
          delegate_to: controller.acme.example.com
          loop:
            - name: instruqt_lab
              mode: '0600'
            - name: instruqt_lab.pub
              mode: '0644'

        - name: Create resource group called rg-lightspeed
          azure.azcollection.azure_rm_resourcegroup:
            name: rg-lightspeed
            location: eastus
          register: rg

        - name: Create virtual network called vnet-lightspeed
          azure.azcollection.azure_rm_virtualnetwork:
            resource_group: rg-lightspeed
            name: vnet-lightspeed
            address_prefixes: 10.0.0.0/16

        - name: Add subnet called subnet-lightspeed
          azure.azcollection.azure_rm_subnet:
            resource_group: rg-lightspeed
            name: subnet-lightspeed
            address_prefix: 10.0.1.0/24
            virtual_network: vnet-lightspeed

        - name: Create public IP address called ip-lightspeed
          azure.azcollection.azure_rm_publicipaddress:
            resource_group: rg-lightspeed
            allocation_method: Static
            name: ip-lightspeed
          register: ip_lightspeed

        - name: Create azure_public_ip var
          ansible.builtin.set_fact:
            azure_public_ip: "{{ ip_lightspeed.state.ip_address }}"

        - name: Create Network Security Group that allows SSH
          azure.azcollection.azure_rm_securitygroup:
            resource_group: rg-lightspeed
            name: secgroup-lightspeed
            rules:
              - name: SSH
                protocol: Tcp
                destination_port_range: 22
                access: Allow
                priority: 1001
                direction: Inbound

        - name: Create virtual network interface
          azure.azcollection.azure_rm_networkinterface:
            resource_group: rg-lightspeed
            name: nic-lightspeed
            virtual_network: vnet-lightspeed
            subnet: subnet-lightspeed
            public_ip_name: ip-lightspeed
            security_group: secgroup-lightspeed

    - name: Solve configure-tools VS Code settings
      ansible.builtin.copy:
        src: "{{ playbook_dir }}/files/settings_workspace_solve.json"
        dest: "~{{ student_username }}/{{ gitea_repo_name }}/.vscode/settings.json"
        owner: "{{ student_username }}"
        group: "{{ student_username }}"
        remote_src: true
        mode: "0644"
      register: __settings_file
      tags:
        - solve-configure-tools

    - name: Check configure-tools present VS Code settings
      tags:
        - check-configure-tools
      block:
        - name: Check Lightspeed config present
          ansible.builtin.lineinfile:
            path: "~{{ student_username }}/{{ gitea_repo_name }}/.vscode/settings.json"
            # path: "~{{ student_username }}/.config/Code/User/settings.json"
            state: absent
            backrefs: true
            regex: "{{ item.regex }}"
            owner: "{{ student_username }}"
            group: "{{ student_username }}"
            mode: "0644"
          check_mode: "{{ check_mode | default(true) }}"
          register: __vscode_lightspeed
          loop: "{{ configure_tools['vscode_settings']['present'] }}"

        - name: Assert __vscode_lightspeed lines found
          ansible.builtin.assert:
            that: 
              - item.found > 0
            fail_msg: The VS Code .vscode/settings.json missing Lightspeed entries.
            success_msg: VS Code Lightspeed config entries present.
          loop: "{{ __vscode_lightspeed.results }}"

    - name: Solve run job templates
      delegate_to: localhost
      awx.awx.job_launch:
        name: "{{ item.name }}"
        wait: true
        <<: *controller_login
      loop: "{{ controller_templates[content_list] }}"
      when: 
        - controller_templates[content_list] is defined
      tags:
        - solve-database-jt
        - solve-monitoring-jt
        - solve-aws-jt
        - solve-azure-jt

    - name: Check EC2 instance is provisioned and running
      delegate_to: localhost
      tags:
        - check-aws-instance
      block:
        - name: Gather EC2 instance info
          amazon.aws.ec2_instance_info:
            filters:
              "tag:Name": "instance-lightspeed-01"
              "tag:function": "demo-lightspeed"
              instance-state-name: ["running"]
          register: ec2_node_info

        - name: Assert that EC2 instance is provisioned and running
          ansible.builtin.assert:
            that:
              - ec2_node_info["instances"] | length > 0
            fail_msg: The EC2 instance is not provisioned and running.
            success_msg: The EC2 instance is provisioned and running.

    - name: Cleanup AWS instance
      delegate_to: localhost
      amazon.aws.ec2_instance:
        state: terminated
        filters:
          "tag:Name": "instance-lightspeed-01"
          "tag:function": "demo-lightspeed"
        wait: false
      tags:
        - cleanup-aws-instance

    - name: Check Azure VM is provisioned and running
      delegate_to: localhost
      azure_rm_virtualmachine_info:
        resource_group: rg-lightspeed
        name: vm-lightspeed
      register: __azure_vm_info
      tags:
        - check-azure-vm

    - name: Remove Azure VM instance
      delegate_to: localhost
      azure.azcollection.azure_rm_virtualmachine:
        state: absent
        name: vm-lightspeed
        resource_group: rg-lightspeed
      tags:
        - cleanup-azure-vm

  

- name: Setup, check, and solve on nodes
  hosts: nodes
  gather_facts: false
  become: true

  vars:
    track_slug: lightspeed-101

  vars_files:
    - track_vars.yml
    - vault_track_vars.yml

  tasks:
    - name: Create pgadmin container
      tags:
        - setup-database-container
      block:
        - name: Get host ansible_facts
          ansible.builtin.setup:

        - name: Run podman container using pgadmin_container var
          containers.podman.podman_container:
            name: "{{ pgadmin_container.name }}"
            image: "{{ pgadmin_container.image }}"
            state: stopped
            ports: "{{ pgadmin_container.ports }}"
            generate_systemd: "{{ pgadmin_container.generate_systemd }}"
            env: "{{ pgadmin_container.env }}"
            network: "{{ pgadmin_container.network }}"

        - name: Manage container service - {{ pgadmin_service_name }}
          ansible.builtin.systemd:
            name: "{{ pgadmin_service_name }}"
            state: "{{ container_service | default('stopped') }}"
            enabled: true
            daemon_reload: true

    - name: Check database - PGAdmin is running
      tags:
        - check-database-app
      block:
        - name: Get container info - "{{ pgadmin_container.name }}"
          containers.podman.podman_container_info:
            name:
              - "{{ pgadmin_container.name }}"
          register: __app_container_info

        - name: Check database - assert container is running
          ansible.builtin.assert:
            that: 
              - '"Error: inspecting object: no such container" not in __app_container_info.stderr'
              - __app_container_info.containers[0]["State"]["Running"]
            fail_msg: "Error inspecting container - {{ pgadmin_container.name }}."
            success_msg: "Successfully inspected container - {{ pgadmin_container.name }}."

    - name: Check monitoring - Cockpit is running
      tags:
        - check-monitoring-cockpit
      block:
        - name: Check and Solve monitoring - Cockpit app is running
          ansible.builtin.systemd:
            name: cockpit.socket
            state: started
          check_mode: "{{ check_mode | default(true) }}"
          register: __cockpit_service

        - name: Check monitoring - assert cockpit is running
          ansible.builtin.assert:
            that: 
              - __cockpit_service["status"]["ActiveState"] == "active"
            fail_msg: "Cockpit service stopped."
            success_msg: "Cockpit service running."

    - name: Check database - Postgresql is running
      tags:
        - check-database-postgresql
      block:
        - name: Check and Solve keywords - Monitor app is running
          ansible.builtin.systemd:
            name: postgresql
            state: started
          check_mode: "{{ check_mode | default(true) }}"
          register: __postgresql_service

        - name: Check database - assert postgresql is running
          ansible.builtin.assert:
            that: 
              - __postgresql_service["status"]["ActiveState"] == "active"
            fail_msg: "Postgresql service stopped."
            success_msg: "Postgresql service running."
EOF

tee /tmp/track_vars.yml << EOF

---
# config vars
ansible_ssh_pipelining: true
ansible_ssh_extra_args: -o StrictHostKeyChecking=no -o ControlMaster=auto -o ControlPersist=60s
ansible_host_key_checking: false

track_slug: lightspeed-101

# controller_hostname: "{{ vault_controller_hostname }}"
# controller_validate_certs: "{{ vault_controller_validate_certs }}"
# controller_username: "{{ vault_controller_username }}"
# controller_password: "{{ vault_controller_password }}"

# student_username: "{{ vault_student_username }}"
# student_password: "{{ vault_student_password }}"

controller_username: "admin"
controller_password: "ansible123!"
controller_host: " http://localhost "
validate_certs: "false
student_username: "student"
student_password: "learn_ansible"


# Lab vars
lab:
  credential_type:
    pub_ssh:
      name: Public SSH key credential type
  credential:
    pub_ssh:
      name: ACME Corp public SSH key
    ssh:
      name: ACME Corp machine credential
    controller:
      name: ACME Corp controller credential
    aws:
      name: ACME Corp AWS credential
    azure:
      name: ACME Corp Azure credential
  organization: ACME Corp
  project:
    name: ACME Corp Repo
    repo: "{{ gitea_app_url }}/{{ student_username }}/acme_corp.git"
    branch: main
  inventory:
    name: ACME Corp DC
    description: ACME Corp Data center
  execution_environment:
    name: ACME Corp execution environment
    image: quay.io/acme_corp/lightspeed-101_ee
  s3_bucket_name: tmm-instruqt-content.demoredhat.com.private
  workflow_name: Database ops workflow
  # navigator_execution_environment: quay.io/acme_corp/lightspeed-101_ee
  navigator_execution_environment:
    name: ACME Corp execution environment
    image: quay.io/acme_corp/lightspeed-101_ee
# Gitea vars
gitea_http_port: 3000
gitea_protocol: https
gitea_hostname: gitea
gitea_app_url: "{{ gitea_protocol }}://{{ gitea_hostname }}:{{ gitea_http_port }}"
gitea_repo_name: acme_corp
# Dev
gitea_clone_address: "https://github.com/ansible/ansible-lightspeed-demos"

configure_tools:
  vscode_settings:
    present:
      - line: '\1"ansible.lightspeed.suggestions.enabled": true\2'
        regex: '^(.*?)"ansible.lightspeed.suggestions.enabled": true(.*?)$'
      - line: '\1"ansible.lightspeed.enabled": true\2'
        regex: '^(.*?)"ansible\.lightspeed\.enabled": true(.*?)$'
    # absent:
    #   - line: '\1"ansible.validation.lint.enabled": false\2'
    #     regex: '^(.*?)"ansible.validation.lint.enabled": false(.*?)$'
    #   - line: '\1"ansible.validation.enabled": false\2'
    #     regex: '^(.*?)"ansible.validation.enabled": false(.*?)$'

monitoring:
  playbooks:
    - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/infra/install_cockpit/demo_install_cockpit.yml"
      source_playbook: "files/solution_playbooks/solution_install_cockpit.yml"
      # remote_src: true
  playbook_names:
    - demo_install_cockpit.yml
  jt_names:
    - Deploy monitoring
apache:
  playbooks:
    - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/infra/install_apache/demo_install_apache.yml"
      source_playbook: "files/solution_playbooks/solution_install_apache.yml"
      # remote_src: true
  playbook_names:
    - demo_install_apache.yml
  jt_names:
    - Deploy Apache webserver
database:
  playbooks:
    - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/infra/install_pgsql_and_pgadmin/demo_install_pgsql_pgadmin.yml"
      source_playbook: "files/solution_playbooks/solution_install_pgsql_pgadmin.yml"
      # remote_src: true
  playbook_names:
    - demo_install_pgsql_pgadmin.yml
  jt_names:
    - Deploy PostgreSQL and PG Admin
aws:
  playbooks:
    - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/cloud/aws/demo_provision_ec2_instance.yml"
      source_playbook: "files/solution_playbooks/solution_provision_ec2_instance.yml"
      # remote_src: true
  playbook_names:
    - demo_provision_ec2_instance.yml
  jt_names:
    - Provision EC2 instance
azure:
  playbooks:
    - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/cloud/azure/demo_provision_azure_vm.yml"
      source_playbook: "files/solution_playbooks/solution_provision_azure_vm.yml"
      # remote_src: true
  playbook_names:
    - demo_provision_azure_vm.yml
  jt_names:
    - Provision Azure VM
# workflow:
#   playbooks:
#     - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/create_workflow.yml"
#       source_playbook: "files/initial_playbooks/create_workflow.yml"
#   jt_names:
#     - Solve - Create database ops workflow
playground:
  playbooks:
    - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/infra/install_cockpit/demo_install_cockpit.yml"
      source_playbook: "files/initial_playbooks/demo_install_cockpit.yml"
    - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/infra/install_pgsql_and_pgadmin/demo_install_pgsql.yml"
      source_playbook: "files/initial_playbooks/demo_install_pgsql_pgadmin.yml"
    - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/cloud/aws/demo_provision_ec2_instance.yml"
      source_playbook: "files/initial_playbooks/demo_provision_ec2_instance.yml"
    - dest_playbook: "~{{ student_username }}/{{ gitea_repo_name }}/playbooks/cloud/azure/demo_provision_azure_vm.yml"
      source_playbook: "files/initial_playbooks/demo_provision_azure_vm.yml"

# PGAdmin container
pgadmin_service_name: app-pgadmin
pgadmin_container:
  name: pgadmin
  image: docker.io/dpage/pgadmin4
  ports:
    - 8083:80
  state: started
  generate_systemd:
    path: /etc/systemd/system/
    container_prefix: app
    restart_policy: always
  network: bridge
  env:
    PGADMIN_DEFAULT_EMAIL: "{{ student_username }}@example.com"
    PGADMIN_DEFAULT_PASSWORD: "{{ student_password }}"
# mattermost_app:
#   env:
#     MM_TEAMSETTINGS_SITENAME: ACME Corp Chat
#   generate_systemd:
#     path: /etc/systemd/system/
#     container_prefix: app
#     restart_policy: always
#   recreate: true
#   name: mattermost-preview
#   image: docker.io/mattermost/mattermost-preview
#   state: started
#   ports:
#     - 8065:8065

# Controller objects
controller_inventories:
  - name: "{{ lab.inventory.name }}"
    organization: "{{ lab.organization }}"
    description: "{{ lab.inventory.name }}"
    variables:
      ansible_ssh_private_key_file: ~/.ssh/instruqt_lab
      ansible_host: "{{ track_slug }}-controller"
      # ansible_host: "lightspeed-101-controller.{{ lookup('env', '_SANDBOX_ID') }}.svc.cluster.local"
      ansible_user: rhel
      ansible_python_interpreter: /usr/bin/python3
      ansible_ssh_extra_args: '-o StrictHostKeyChecking=no -o ControlMaster=auto -o ControlPersist=60s'
      ansible_ssh_pipelining: true

controller_credentials:
  # - name: "{{ lab.credential.controller.name }}"
  #   organization: "{{ lab.organization }}"
  #   credential_type: Red Hat Ansible Automation Platform
  #   description: "{{ lab.credential.controller.name }}"
  #   state: present
  #   inputs:
  #     host: "{{ controller_hostname }}.{{ lookup('env', '_SANDBOX_ID') }}.svc.cluster.local"
  #     verify_ssl: "{{ controller_validate_certs }}"
  #     username: "{{ controller_username }}"
  #     password: "{{ controller_password }}"

  #  Might be temp - depends on if we stick with this format
  playground:
    - name: "{{ lab.credential.aws.name }}"
      organization: "{{ lab.organization }}"
      credential_type: Amazon Web Services
      description: "{{ lab.credential.aws.name }}"
      state: present
      inputs:
        username: "{{ lookup('env', 'AWS_ACCESS_KEY_ID', default='empty') }}"
        password: "{{ lookup('env', 'AWS_SECRET_ACCESS_KEY', default='empty') }}"
    - name: "{{ lab.credential.azure.name }}"
      organization: "{{ lab.organization }}"
      credential_type: Microsoft Azure Resource Manager
      description: "{{ lab.credential.azure.name }}"
      state: present
      inputs:
        # Can't use proper Azure vars here created in setup-env section.
        client: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_SPN_ID') }}"
        secret: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_SPN_PASSWORD') }}"
        subscription: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_SUBSCRIPTION_ID') }}"
        tenant: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_TENANT_ID') }}"
        username: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_USERNAME') }}"
        password: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_PASSWORD') }}"
  aws:
    - name: "{{ lab.credential.aws.name }}"
      organization: "{{ lab.organization }}"
      credential_type: Amazon Web Services
      description: "{{ lab.credential.aws.name }}"
      state: present
      inputs:
        username: "{{ lookup('env', 'AWS_ACCESS_KEY_ID', default='empty') }}"
        password: "{{ lookup('env', 'AWS_SECRET_ACCESS_KEY', default='empty') }}"
  azure:
    - name: "{{ lab.credential.azure.name }}"
      organization: "{{ lab.organization }}"
      credential_type: Microsoft Azure Resource Manager
      description: "{{ lab.credential.azure.name }}"
      state: present
      inputs:
        client: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_SPN_ID') }}"
        secret: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_SPN_PASSWORD') }}"
        subscription: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_SUBSCRIPTION_ID') }}"
        tenant: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_TENANT_ID') }}"
        username: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_USERNAME') }}"
        password: "{{ lookup('ansible.builtin.env', 'INSTRUQT_AZURE_SUBSCRIPTION_AZUREADMIN_PASSWORD') }}"

controller_templates:
  # Temp - if this works build into image
  playground:
    - name: Provision Azure VM
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/cloud/azure/demo_provision_azure_vm.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.azure.name }}"
        - "{{ lab.credential.pub_ssh.name }}"
      project: "{{ lab.project.name }}"
      extra_vars:
        pub_key_data: "{{ lookup('ansible.builtin.file', '~/.ssh/instruqt_lab.pub') }}"
    - name: Provision EC2 instance
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/cloud/aws/demo_provision_ec2_instance.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.aws.name }}"
      project: "{{ lab.project.name }}"
    - name: Deploy monitoring
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/infra/install_cockpit/demo_install_cockpit.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.ssh.name }}"
      project: "{{ lab.project.name }}"
    - name: Deploy Apache webserver
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/infra/install_apache/demo_install_apache.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.ssh.name }}"
      project: "{{ lab.project.name }}"
    - name: Deploy PostgreSQL and PG Admin
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/infra/install_pgsql_and_pgadmin/demo_install_pgsql_pgadmin.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.ssh.name }}"
      project: "{{ lab.project.name }}"
  azure:
    - name: Provision Azure VM
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/cloud/azure/demo_provision_azure_vm.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.azure.name }}"
        - "{{ lab.credential.pub_ssh.name }}"
      project: "{{ lab.project.name }}"
      extra_vars:
        pub_key_data: "{{ lookup('ansible.builtin.file', '~/.ssh/instruqt_lab.pub') }}"
    # - name: Prepare Azure demo
    #   state: present
    #   job_type: run
    #   playbook: "playbooks/cloud/azure/prepare_azure_environment.yml"
    #   execution_environment: "{{ lab.execution_environment.name }}"
    #   organization: "{{ lab.organization }}"
    #   inventory: "{{ lab.inventory.name }}"
    #   verbosity: 0
    #   credentials:
    #     - "{{ lab.credential.azure.name }}"
    #   project: "{{ lab.project.name }}"
    #   extra_vars:
    #     _SANDBOX_ID: "{{ lookup('ansible.builtin.env', '_SANDBOX_ID') }}" # Updated in lifecycle script.
  aws:
    - name: Provision EC2 instance
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/cloud/aws/demo_provision_ec2_instance.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.aws.name }}"
      project: "{{ lab.project.name }}"
    # - name: Prepare AWS demo
    #   state: present
    #   job_type: run
    #   playbook: "playbooks/cloud/aws/prepare_aws_environment.yml"
    #   execution_environment: "{{ lab.execution_environment.name }}"
    #   organization: "{{ lab.organization }}"
    #   inventory: "{{ lab.inventory.name }}"
    #   verbosity: 0
    #   credentials:
    #     - "{{ lab.credential.aws.name }}"
    #   project: "{{ lab.project.name }}"
    #   extra_vars:
    #     _SANDBOX_ID: "{{ lookup('ansible.builtin.env', '_SANDBOX_ID') }}" # Updated in lifecycle script.
  monitoring:
    - name: Deploy monitoring
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/infra/install_cockpit/demo_install_cockpit.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.ssh.name }}"
      project: "{{ lab.project.name }}"
  apache:
    - name: Deploy Apache webserver
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/infra/install_apache/demo_install_apache.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.ssh.name }}"
      project: "{{ lab.project.name }}"
  database:
    - name: Deploy PostgreSQL and PG Admin
      organization: "{{ lab.organization }}"
      state: present
      job_type: run
      playbook: "playbooks/infra/install_pgsql_and_pgadmin/demo_install_pgsql_pgadmin.yml"
      execution_environment: "{{ lab.execution_environment.name }}"
      inventory: "{{ lab.inventory.name }}"
      credentials:
        - "{{ lab.credential.ssh.name }}"
      project: "{{ lab.project.name }}"
    # - name: Configure PGAdmin container
    #   organization: "{{ lab.organization }}"
    #   state: present
    #   job_type: run
    #   playbook: "playbooks/infra/install_pgsql_and_pgadmin/demo_pgadmin_podman.yml"
    #   execution_environment: "{{ lab.execution_environment.name }}"
    #   inventory: "{{ lab.inventory.name }}"
    #   credentials:
    #     - "{{ lab.credential.ssh.name }}"
    #   project: "{{ lab.project.name }}"
  # workflow:
  #   - name: Solve - Create database ops workflow
  #     state: present
  #     job_type: run
  #     playbook: "playbooks/create_workflow.yml"
  #     execution_environment: "{{ lab.execution_environment.name }}"
  #     organization: "{{ lab.organization }}"
  #     inventory: "{{ lab.inventory.name }}"
  #     verbosity: 0
  #     credentials:
  #       - "{{ lab.credential.ssh.name }}"
  #       - "{{ lab.credential.controller.name }}"
  #     project: "{{ lab.project.name }}"

# controller_workflows:
#   - name: "{{ lab.workflow_name }}"
#     description: "{{ lab.workflow_name }}"
#     organization: "{{ lab.organization }}"

# controller_workflow_nodes:
#   - all_parents_must_converge: false
#     organization: "{{ lab.organization }}"
#     workflow_job_template: "{{ lab.workflow_name }}"
#     identifier: Database
#     unified_job_template: Deploy PostgreSQL database
#     success_nodes:
#       - PGAdmin
#   - all_parents_must_converge: false
#     organization: "{{ lab.organization }}"
#     workflow_job_template: "{{ lab.workflow_name }}"
#     identifier: PGAdmin
#     unified_job_template: Configure PGAdmin container


EOF

##
export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

##
##ANSIBLE_COLLECTIONS_PATH=/tmp/ansible-automation-platform-containerized-setup-bundle-2.5-9-x86_64/collections/:/root/.ansible/collections/ansible_collections/ ansible-playbook -i /tmp/inventory /tmp/setup.yml

