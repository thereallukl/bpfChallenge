# BPF Challenge

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
docker run -t --net=host -v /lib/modules:/lib/modules -v /usr/src/:/usr/src/ -v /usr/include:/usr/include --privileged bpf-challenge <interface_name>
```