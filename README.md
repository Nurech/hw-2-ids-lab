# Intrusion Detection System (IDS) lab - Suricata Student version 2023 (Ansible automated)

Run:
```
sudo wget "https://raw.githubusercontent.com/Nurech/hw-2-ids-lab/master/playbook.yaml" -O playbook.yaml && \
sudo chown $USER:$USER playbook.yaml && \
chmod +x playbook.yaml && \
sudo wget "https://raw.githubusercontent.com/Nurech/hw-2-ids-lab/master/start.sh" -O start.sh && \
sudo chown $USER:$USER start.sh && \
chmod +x start.sh && \
./start.sh
```


1) Downloads [start.sh](https://github.com/Nurech/hw-2-ids-lab/blob/master/start.sh) (Install Ansible on system)
2) Downloads [playbook.yaml](https://github.com/Nurech/hw-2-ids-lab/blob/master/playbook.yaml) (Ansible playbook)
3) Run ``playbook.yaml`` to automate hw-2 Suricata setup

Tested on:\
VMWARE Workstation 16 \
No LSB modules are available.\
Distributor ID:	Ubuntu\
Description:	Ubuntu 22.04.3 LTS\
Release:	22.04\
Codename:	jammy\

