FROM ubuntu:21.10 as builder
WORKDIR /app
COPY . .
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y golang-go build-essential libpcap-dev libbpfcc-dev libbpf-dev bpfcc-tools linux-headers-`uname -r`
RUN go mod download

RUN GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o main main.go

FROM ubuntu:21.10
RUN apt update && \
    apt install -y libpcap0.8  bcc libbpfcc
COPY --from=builder /app/main /
ENTRYPOINT ["/main"]