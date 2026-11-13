FROM alpine:3.20
RUN apk add --no-cache tcpdump
CMD ["tcpdump", "-i", "eth0", "-n", "-U", "-s", "160", "-w", "/captures/lab.pcap"]
