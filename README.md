# Intrusion Detection System (IDS) lab - Suricata Student version 2023 (Ansible automated)

Source: https://github.com/Nurech/hw-2-ids-lab

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
Distributor ID:	Ubuntu\
Description:	Ubuntu 22.04.3 LTS\
Release:	22.04\
Codename:	jammy\

# Answers:

### The Hping send TCP packets to your device on port 80, What should be the signature header?
The basic signature looks like this (this is alert type source -> target protected/monitored):
````shell
alert tcp any any -> 1.1.1.1 80
````
### To detect the DOS attack Suricata needs to keep track of the number of packets received within a timeframe. How do you think the rule options can be written?
When 50 packets sent in 5 seconds, from one source, then alert with message "Possible DOS attack":
````shell
root@ubuntu-virtual-machine:/etc/suricata/rules# cat ddos.rules
alert tcp any any -> 1.1.1.1 80 (msg:"Possible DOS attack"; flags:S; threshold:type both, track by_src, count 50, seconds 5; sid:1000001;)
````
### What is the command for running Suricata with the newly created rule file?
I appended the above to a file ``ddos.rules``
````shell
- name: Create Suricata DDoS rule
  copy:
    content: |
      alert tcp any any -> 1.1.1.1 80 (msg: "Possible DDoS attack"; flags: S; flow: stateless; threshold: type both, track by_dst, count 200, seconds 1; sid:1000001; rev:1;)
    dest: "{{ new_rule_location }}/ddos.rules"
  become: yes
````
I consume the rule file in the ``suricata.yaml`` file:
````shell
   default-rule-path: /etc/suricata/rules
   rule-files:
     - ddos.rules
````
I apply the rule with `sudo suricatasc -c reload-rules`, but for conveneince I do:
````shell
sudo suricata -T -c /etc/suricata/suricata.yaml \
&& sudo suricata-update \
&& sudo systemctl restart suricata \
&& sudo journalctl -u suricata \
&& sudo systemctl status suricata \
&& sudo suricatasc -c reload-rules \
&& sudo suricata --dump-config | grep -i rule-files
````
Verify:
````shell
root@ubuntu-virtual-machine:/home/ubuntu/Desktop/suricata_ansible# suricata --dump-config | grep -i rule-files
rule-files = (null)
rule-files.0 = ddos.rules
````
### While Suricata is running, run the hping command to generate the traffic. After a few seconds (depends on the timeframe that you define in your rule), check the logs, do you see any alerts?
Sending packets:
````shell
root@ubuntu-virtual-machine:/home/ubuntu/Desktop# sudo hping3 -S -p 80 --flood --rand-source 1.1.1.1
HPING 1.1.1.1 (ens33 1.1.1.1): S set, 40 headers + 0 data bytes
hping in flood mode, no replies will be shown
^C
--- 1.1.1.1 hping statistic ---
20119 packets transmitted, 0 packets received, 100% packet loss
round-trip min/avg/max = 0.0/0.0/0.0 ms

````
I monitor the port to see if hping is working. Yes it is:
````shell
root@ubuntu-virtual-machine:/home/ubuntu/Desktop/suricata_ansible# sudo tcpdump -i ens33 -nn host 1.1.1.1
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens33, link-type EN10MB (Ethernet), snapshot length 262144 bytes
13:48:25.222984 IP 113.176.177.34.2757 > 1.1.1.1.80: Flags [S], seq 1588306381, win 512, length 0
13:48:25.223129 IP 41.232.130.176.2758 > 1.1.1.1.80: Flags [S], seq 694056831, win 512, length 0
13:48:25.223178 IP 173.99.79.158.2759 > 1.1.1.1.80: Flags [S], seq 442233126, win 512, length 0
...
````
I see alert triggered in fast.log (example taken from [here](https://forum.suricata.io/t/rule-doesnt-load/522/3)):
````shell
root@ubuntu-virtual-machine:/home/ubuntu/Desktop# sudo tail -f /var/log/suricata/fast.log
10/07/2023-14:17:33.075237  [**] [1:1000001:1] Possible DDoS attack [**] [Classification: (null)] [Priority: 3] {TCP} 222.18.242.56:13272 -> 1.1.1.1:80
10/07/2023-14:17:34.133678  [**] [1:1000001:1] Possible DDoS attack [**] [Classification: (null)] [Priority: 3] {TCP} 242.26.9.207:18026 -> 1.1.1.1:80
...
````


#### Review the traffic in Wireshark, what do you think is the possible source of the infection?
#### What is the IP address of the host which is the source of the infected file?
#### What is the URL requested?
#### What is the name of the downloaded file?
#### What is the name of the malware the host was infected with?
#### What is the HTTPS traffic caused by the word document Macro for the malware?
#### Can you identify the post infection caused by Emotet?
#### Can you identify the post infection caused by TrickBot?
#### What are the hosts that malicious files have been downloaded from?
#### What are the malicious files SHA256 checksum?
