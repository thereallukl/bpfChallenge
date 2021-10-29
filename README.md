# BPF Challenge

BPF challenge app was developed and tested on ubuntu 21.10. For time being it's only supported distribution
## Dependencies
install required packages
```
apt update
apt install -y \
    golang-go \
    build-essential \
    libpcap-dev \
    libbpfcc-dev \
    libbpf-dev \
    bpfcc-tools \
    linux-headers-$(uname -r) \
    linux-headers-generic \
    libpcap0.8 \
    bcc
```

## Build locally
Run makefile to build 
```bash
make build
```

Run
```bash
sudo ./main <interface_name>
```

## Build in docker
Run makefile to build image
```bash
make docker
```

Run app in docker container
```bash
// install linux-headers on host
apt update && apt install -y linux-headers-generic
docker run -t --net=host -v /lib/modules:/lib/modules --privileged bpf-challenge <interface_name>
```

## Troubleshooting
In case application crashes and fail to unload BPF program upon exit, user can manually remove it
```bash
sudo ip l set dev <interface_name> xdpgeneric off
```