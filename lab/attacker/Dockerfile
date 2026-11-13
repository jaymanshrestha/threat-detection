FROM python:3.12-alpine
# nmap from the main repo; hping3 lives in Alpine's "testing" repo - if it can't be installed,
# attack.py falls back to its pure-Python raw-socket SYN sender (same packets, same rate cap).
RUN apk add --no-cache nmap nmap-scripts \
 && (apk add --no-cache hping3 --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing || echo "hping3 unavailable - Python SYN sender will be used")
WORKDIR /lab
COPY attack.py /lab/attack.py
CMD ["python", "/lab/attack.py", "--target", "10.66.0.10", "--out", "/captures/attack_phases.json"]
