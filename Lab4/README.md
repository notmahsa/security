## Lab 4: DNS Nameserver Spoofing and Cache Poisoning
### Part 1:
In this part I ran simple dig commands to test the BIND server. Use the following to run the dig command:
```
    ./run_bind.sh
    dig @localhost -p 1541 example.com
```

### Part 2:
In this part I built a simple dns proxy, using python. Nothing we haven't seen before. 

### Part 3:
I changed the ns records on the reseponse for DNS spoofing. Use the following to run:
```
    ./run_bind.sh
    python dnsproxy_starter.py --port 9090 --dns_port 1541 --spoof_response
    dig @localhost -p 9090 example.com
```

### Part 4:
In this part, I changed the port up a little, since it was confusing. The script floods random sub domains of example.com and tries to poison the NS cache for the base example.com domain. Run using the following:
```
    ./run_bind.sh
    python part4_starter.py --ip 127.0.0.1 --query_port 18883 --dns_port 1541 --port 9090
```
