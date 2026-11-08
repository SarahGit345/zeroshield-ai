"""Extract plaintext HTTP requests from a PCAP/PCAPNG file (plan amendment 3).

    python pcap_http_extract.py CAPTURE.pcap --out requests.jsonl [--label SqlInjection]

Client-to-server TCP payloads are reassembled per connection in sequence order (duplicates dropped),
starting at a segment that begins with an HTTP method on any port, and parsed with dpkt. One JSON line
per request: file, label, timestamp, connection 4-tuple, method, URI, host, content type, headers
needed by the content check, and the body (first 64 KB, decoded as latin-1 so bytes survive).
TLS connections are counted, not read. Limits: no handling of gaps (lost segments end a connection's
parsing), pipelined requests are parsed in order, HTTP/2 is not supported.
"""
from __future__ import annotations

import argparse
import json
import socket
from collections import Counter
from pathlib import Path

import dpkt

METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
MAX_CONNECTION_BYTES = 2 * 1024 * 1024
MAX_BODY = 65536


def _reader(handle):
    head = handle.read(4); handle.seek(0)
    return dpkt.pcapng.Reader(handle) if head == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(handle)


def _ip_of(buf, linktype):
    try:
        if linktype == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf); ip = eth.data
        elif linktype in (dpkt.pcap.DLT_RAW, 101):
            ip = dpkt.ip.IP(buf) if (buf[0] >> 4) == 4 else dpkt.ip6.IP6(buf)
        elif linktype == dpkt.pcap.DLT_LINUX_SLL:
            ip = dpkt.sll.SLL(buf).data
        else:
            return None
    except Exception:
        return None
    return ip if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)) else None


def _addr(ip, raw):
    return socket.inet_ntop(socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6, raw)


def iter_requests(path: Path, label: str | None = None, stats: Counter | None = None):
    stats = stats if stats is not None else Counter()
    conns: dict[tuple, dict] = {}
    with open(path, "rb") as handle:
        reader = _reader(handle)
        linktype = reader.datalink()
        for ts, buf in reader:
            stats["packets"] += 1
            ip = _ip_of(buf, linktype)
            if ip is None or not isinstance(ip.data, dpkt.tcp.TCP): continue
            tcp = ip.data
            payload = bytes(tcp.data)
            if not payload: continue
            key = (_addr(ip, ip.src), tcp.sport, _addr(ip, ip.dst), tcp.dport)
            conn = conns.get(key)
            if conn is None:
                if payload[:3] == b"\x16\x03\x01" or payload[:3] == b"\x16\x03\x03":
                    stats["tls_client_hellos"] += 1
                if not payload.startswith(METHODS): continue
                conn = conns[key] = {"segments": {}, "first_ts": ts, "size": 0}
            if tcp.seq in conn["segments"] or conn["size"] >= MAX_CONNECTION_BYTES: continue
            conn["segments"][tcp.seq] = (ts, payload); conn["size"] += len(payload)
    for key, conn in conns.items():
        yield from _parse_connection(path, label, key, conn, stats)


def _parse_connection(path, label, key, conn, stats):
    ordered = sorted(conn["segments"].items())
    data, expected, ts0 = b"", None, conn["first_ts"]
    for seq, (ts, payload) in ordered:
        if expected is not None and seq != expected:
            stats["connections_with_gaps"] += 1; break
        data += payload; expected = (seq + len(payload)) & 0xFFFFFFFF
    while data:
        try:
            req = dpkt.http.Request(data)
        except (dpkt.NeedData, dpkt.UnpackError):
            if data.startswith(METHODS): stats["unparsed_requests"] += 1
            break
        stats["requests"] += 1
        headers = {k: v if isinstance(v, str) else ",".join(v) for k, v in req.headers.items()}
        body = bytes(req.body or b"")[:MAX_BODY].decode("latin-1")
        yield {"file": Path(path).name, "label": label, "ts": ts0, "src": key[0], "sport": key[1], "dst": key[2], "dport": key[3],
               "method": req.method, "uri": req.uri, "host": headers.get("host"), "content_type": headers.get("content-type"),
               "headers": {k: v for k, v in headers.items() if k in ("content-disposition", "user-agent", "content-type")},
               "body": body}
        rest = bytes(getattr(req, "data", b"") or b"")        # dpkt leaves bytes after this request here
        if len(rest) >= len(data): break
        data = rest


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("capture", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--label")
    args = p.parse_args(argv)
    stats = Counter()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as f:
        for req in iter_requests(args.capture, args.label, stats):
            f.write(json.dumps(req) + "\n")
    print(json.dumps(dict(stats)))


if __name__ == "__main__":
    main()
