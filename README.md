# Intrusion Detection System (IDS) lab - Suricata Student version 2023 (Ansible automated)

Source: https://github.com/Nurech/hw-2-ids-lab

Run:
```
sudo wget "https://raw.githubusercontent.com/Nurech/hw-2-ids-lab/master/playbook.yaml" -O playbook.yaml && \
sudo chown $USER:$USER playbook.yaml && \
chmod +x playbook.yaml && \
sudo wget "https://raw.githubusercontent.com/Nurech/hw-2-ids-lab/master/start.sh" -O start.sh && \
sudo chown $USER:$USER start.sh && \
sudo wget "https://github.com/Nurech/hw-2-ids-lab/raw/master/sample_traffic.pcap" -O sample_traffic.pcap && \
sudo chown $USER:$USER sample_traffic.pcap && \
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
#### Test the rule, do you see any alerts? 
No not yet because I don't know who is the host. 
#### Find the infected host IP address. Check the alerts in the log file and look for the IP addresses in the alerts. What is the IP address of the possible infected host?
Host is probably the infected host ``10.20.30.101`` as it making realistic lookind DNS and HTTP requests:
````shell
1	0.000000	10.20.30.101	10.20.30.1	DNS	73	Standard query 0x5dd2 A ikosher.co.il
2	0.252134	10.20.30.1	10.20.30.101	DNS	105	Standard query response 0x5dd2 A ikosher.co.il A 104.28.7.44 A 104.28.6.44
3	0.255520	10.20.30.101	104.28.7.44	TCP	66	49677 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
4	0.530331	104.28.7.44	10.20.30.101	TCP	58	80 → 49677 [SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0 MSS=1460
5	0.530871	10.20.30.101	104.28.7.44	TCP	54	49677 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0
6	0.532518	10.20.30.101	104.28.7.44	HTTP	683	GET /discussiono/multifunctional-section/close-4hfy6o73iy-06x/383167265-j3LVOCu77d3B/ HTTP/1.1 
````
#### Find infected host MAC address
````shell
Source: HewlettP_1c:47:ae (00:08:02:1c:47:ae)
````
#### What is the URL requested?
It probably started here.
````shell
6	0.532518	10.20.30.101	104.28.7.44	HTTP	683	GET /discussiono/multifunctional-section/close-4hfy6o73iy-06x/383167265-j3LVOCu77d3B/ HTTP/1.1 
````
#### Review the traffic in Wireshark, what do you think is the possible source of the infection?
ikosher.co.il (IP: ``104.28.7.44``) and subsequent POST requests to IP addresses like ``173.231.214.60`` and ``190.6.193.152``. 
We see HTTP POST requests to URLs like ``/wbFcaqy5zdJxDV`` and ``/v4ZuR6CnU``.
````shell
1	0.000000	10.20.30.101	10.20.30.1	DNS	73	Standard query 0x5dd2 A ikosher.co.il
````
#### What is the IP address of the host which is the source of the infected file?
````shell
Destination Address: 203.176.135.102
````
#### What is the URL requested?
````shell
3464	1131.464204	10.20.30.101	203.176.135.102	HTTP	264	POST /mor84/DESKTOP-83TKHSQ_W10018363.572D588D45894026346E8F90E07B31E6/81/ HTTP/1.1
[Full request URI: http://203.176.135.102:8082/mor84/DESKTOP-83TKHSQ_W10018363.572D588D45894026346E8F90E07B31E6/90] 
````
#### What is the name of the downloaded file?
````shell
383167265-j3LVOCu77d3B
````
#### What is the name of the malware the host was infected with?
````shell
emotet
````
#### What is the IP address of the host which is the source of the infected file?
````shell
203.176.135.102
````
#### What is the HTTPS traffic caused by the word document Macro for the malware?
#### Can you identify the post infection caused by Emotet?
````shell
507	65.215913	10.20.30.101	190.6.193.152	HTTP	841	POST /wbFcaqy5zdJxDV HTTP/1.1  (application/x-www-form-urlencoded)
1895	226.475842	10.20.30.101	200.69.224.73	HTTP	845	POST /OwgR HTTP/1.1  (application/x-www-form-urlencoded)
````
#### Can you identify the post infection caused by TrickBot?
````shell
POST /mor84/DESKTOP-83TKHSQ_W10018363.572D588D45894026346E8F90E07B31E6/81/ HTTP/1.1
Accept: */*
Content-Type: multipart/form-data; boundary=---------SEPEGOULLQWDBCNV
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
Host: 203.176.135.102:8082
Content-Length: 219
Connection: Close
Cache-Control: no-cache

-----------SEPEGOULLQWDBCNV
Content-Disposition: form-data; name="data"



-----------SEPEGOULLQWDBCNV
Content-Disposition: form-data; name="source"

OpenVPN passwords and configs
-----------SEPEGOULLQWDBCNV--
HTTP/1.1 200 OK
connection: close
server: Cowboy
date: Mon, 27 Jan 2020 21:10:59 GMT
content-length: 3
Content-Type: text/plain

/1/
````
#### What are the hosts that malicious files have been downloaded from? 
````shell
203.176.135.102
190.214.13.2
104.28.7.44
````
#### What are the malicious files SHA256 checksum?
````shell
383167265-j3LVOCu77d3B 	
c963c83bc1fa7d5378c453463ce990d85858b7f96c08e9012a7ad72ea063f31e
````
