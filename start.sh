# Update package list
sudo apt update || true

# Install software-properties-common
sudo apt install -y software-properties-common

# Add Ansible PPA and install Ansible if not already installed
if ! command -v ansible &> /dev/null; then
  sudo apt-add-repository --yes --update ppa:ansible/ansible
  sudo apt install -y ansible
fi

# Verify Ansible installation
if ! command -v ansible &> /dev/null; then
  echo "Ansible not installed, exiting."
  exit 1
fi

# Create suricata_ansible folder on the user's Desktop if not exists
if [ ! -d "${HOME}/Desktop/suricata_ansible" ]; then
  mkdir -p "${HOME}/Desktop/suricata_ansible"
fi

# Run Ansible playbook
if ansible-playbook "${HOME}/Desktop/suricata_ansible/playbook.yaml"; then
  echo "Ansible playbook ran successfully"
else
  echo "Failed to run Ansible playbook"
  exit 1
fi
