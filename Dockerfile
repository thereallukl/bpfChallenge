FROM golang:1.16-alpine as builder
WORKDIR /app
COPY . .
RUN go mod download
RUN apk update && apk add build-base libpcap-dev libpcap
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o main main.go

FROM alpine
RUN apk update && \
    apk add libpcap
COPY --from=builder /app/main /
ENTRYPOINT ["/main"]