# BPF Challenge

BPF challenge app was developed and tested on ubuntu 21.10. For time being it's only supported platform.

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
docker run -t --net=host --privileged bpf-challenge <interface_name>
```

## Troubleshooting
In case application crashes and fail to unload BPF program upon exit, user can manually remove it
```bash
sudo ip l set dev <interface_name> xdpgeneric off
```

## Test in vagrant
1. Install vagrant
2. Install vagrant with package manager of choice.
3. Install vagrant scp plugin `vagrant plugin install vagrant-scp`
4. Start a VM `cd vagrant; vagrant up`
5. SSH to VM `vagrant ssh`
6. Install packages mentioned in [Dependencies](#dependencies)
7. Copy binary `vagrant scp main main`
8. SSH to VM and start bpf challenge app `sudo ./main <interface_name>`
9. Open separate shell window on the host. Test behaviour with curl `curl http://192.168.33.100:<port_number_of_choice>`
