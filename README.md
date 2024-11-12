# while list ip server

Used to access your server using dynamic IP

## use

Edit `/etc/wip.conf` to configure your password sha256 value, bind ip and bind port(UDP)  
You can use the `read -s -p "input your password: " password && echo -n $password | sha256sum` command to generate sha256

```bash
# configure your firewall to open wip service port
# example: firewalld
firewall-cmd --add-port={{ port }}/udp --permanent
firewall-cmd --add-port={{ port }}/udp

# enable wip server
systemctl enable --now wip
```

## client

Use `nc` or other commands that can send UDP packets

```bash
read -s -p "input your password: " password && echo -n $password | nc -w 
```