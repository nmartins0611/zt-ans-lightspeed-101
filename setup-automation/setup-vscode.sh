#!/bin/bash
curl -k  -L https://${SATELLITE_URL}/pub/katello-server-ca.crt -o /etc/pki/ca-trust/source/anchors/${SATELLITE_URL}.ca.crt
update-ca-trust
rpm -Uhv https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm

subscription-manager register --org=${SATELLITE_ORG} --activationkey=${SATELLITE_ACTIVATIONKEY}
setenforce 0

echo "%rhel ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/rhel_sudoers
# chmod 440 /etc/sudoers.d/rhel_sudoers
# sudo -u rhel mkdir -p /home/rhel/.ssh
# sudo -u rhel chmod 700 /home/rhel/.ssh
# sudo -u rhel ssh-keygen -t rsa -b 4096 -C "rhel@$(hostname)" -f /home/rhel/.ssh/id_rsa -N ""
# sudo -u rhel chmod 600 /home/rhel/.ssh/id_rsa*

systemctl stop firewalld
systemctl stop code-server
mv /home/rhel/.config/code-server/config.yaml /home/rhel/.config/code-server/config.bk.yaml

tee /home/rhel/.config/code-server/config.yaml << EOF
bind-addr: 0.0.0.0:8080
auth: none
cert: false
EOF

systemctl start code-server
#Enable linger for the user `rhel`
loginctl enable-linger rhel
dnf install ansible-core nano git -y

# Install required VSCode extensions
echo "Installing Red Hat Authentication extension..."
wget "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/redhat/vsextensions/vscode-redhat-account/latest/vspackage" -O /tmp/redhat-account.vsix
sudo -u rhel code-server --install-extension /tmp/redhat-account.vsix

echo "Installing Ansible extension..."
wget "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/redhat/vsextensions/ansible/latest/vspackage" -O /tmp/ansible.vsix
sudo -u rhel code-server --install-extension /tmp/ansible.vsix


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
 






EOF





##git clone https://gitea:3000/ansible-lightspeed-demos /home/rhel/acme_corp/



# This is just a stop-gap fix
# cat <<EOF > /home/student/acme_corp/playbooks/infra/install_cockpit/demo_install_cockpit.yml
# ---
# - name: Install and configure Cockpit
#   hosts: rhel
#   become: true
#   tasks:
# ################################################# INSTRUCTIONS TASK 1 #################################################
# # Uncomment the line just after this instructions block and Press "ENTER" at the end.
# # Press "TAB" to accept suggestion.
# # Note - The suggestion included Ansible best practices by using Fully Qualified Collection name (FQCN).
# # Note - The suggestion used the Certified Content Collection specified in the prompt.
# #######################################################################################################################

#     #- name: Install cockpit using redhat.rhel_system_roles package

# ################################################# INSTRUCTIONS TASK 2 #################################################
# # Uncomment the line just after this instructions block and Press "ENTER" at the end.
# # Press "TAB" to accept suggestion.
# # Note - Ansible Lightspeed used "ansible.builtin.template" module based on the ".j2" file extension.
# # Note - The suggestion set the file permissions ("0644"), owner, and group based on Ansible best practices.
# #######################################################################################################################

#     #- name: Copy cockpit.conf.j2 to /etc/cockpit

# ############################################## INSTRUCTIONS TASK 3 and 4 ##############################################
# # Press "ENTER" at the end of the multi-task prompt line just after this instructions block. DO NOT UNCOMMENT THE LINE.
# # Press "TAB" to accept suggestion.
# # First task note - Ansible Lightspeed used the generic "Restart and enable service" prompt
# # and full Playbook context to infer the recommendation should restart the "cockpit" service.
# # Second task note -Ansible Lightspeed used the generic language prompt and Playbook context
# # and used the correct default Cockpit service port (9090) in the suggestion.
# #######################################################################################################################

#     # Restart and enable service & wait 15 seconds for it to be available

# EOF
