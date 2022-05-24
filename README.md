# lVPN

HUST CSE ddVPN++

```shell
sudo iptables -F
sudo iptables -P FORWARD ACCEPT
sudo sysctl net.ipv4.ip_forward=1

git clone https://github.com/lzlzymy/lVPN
cd lVPN
mkdir build && mkdir logs
cd build
cmake ..
make
cd ../docker
docker-compose up -d
```

第二版。
