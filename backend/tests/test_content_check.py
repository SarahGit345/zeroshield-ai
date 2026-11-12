"""HTTP content check (plan amendment 3): frozen rules hit known attack patterns and leave ordinary
requests alone; requests are extracted from synthetic PCAPs (split segments, pipelining, TLS skipped);
the evaluation reports hit rates and benign false positives. No real capture is needed."""
import json
import socket
import tempfile
import unittest
from pathlib import Path

import dpkt

import evaluate_content_check as evaluate
import pcap_http_extract as extract
from services import content_rules as cr


def cats(method="GET", uri="/", body="", headers=None):
    return {h["category"] for h in cr.scan_request(method, uri, body, headers)}


class RuleTests(unittest.TestCase):
    def test_attack_patterns_hit(self):
        self.assertIn("sql_injection", cats(uri="/item.php?id=1 UNION SELECT user,pass FROM users"))
        self.assertIn("sql_injection", cats(uri="/login?u=admin%27%20OR%20%271%27%3D%271"))          # URL-encoded
        self.assertIn("sql_injection", cats(uri="/login?u=admin%2527%2520--"))                       # double-encoded
        self.assertIn("sql_injection", cats(uri="/p?id=1 and sleep(5)"))
        self.assertIn("xss", cats(uri="/search?q=<script>alert(1)</script>"))
        self.assertIn("xss", cats(method="POST", uri="/c", body="msg=<img src=x onerror=alert('x')>"))
        self.assertIn("command_injection", cats(uri="/ping.php?ip=127.0.0.1;cat /etc/passwd"))
        self.assertIn("command_injection", cats(method="POST", uri="/exec", body="host=8.8.8.8 | whoami"))
        self.assertIn("path_traversal", cats(uri="/view?file=../../../../etc/passwd"))
        self.assertIn("web_shell", cats(method="POST", uri="/upload", body='Content-Disposition: form-data; name="f"; filename="shell.php"'))
        self.assertIn("web_shell", cats(method="POST", uri="/x.php", body="<?php system($_GET['c']); ?>"))

    def test_ordinary_requests_do_not_hit(self):
        for method, uri, body in [
            ("GET", "/index.html", ""), ("GET", "/products?select=red&order=asc", ""), ("GET", "/union-station/map", ""),
            ("GET", "/api/v1/status?id=42", ""), ("POST", "/login", "user=alice&password=s3cret"),
            ("POST", "/api", '{"name": "O\'Brien", "note": "rock and roll"}'), ("GET", "/docs/../img/logo.png", ""),
            ("GET", "/search?q=how+to+cook+rice", ""), ("POST", "/upload", 'filename="holiday.jpg"'),
            ("GET", "/script.js", ""), ("GET", "/description?text=on+load+balancing", "")]:
            self.assertEqual(cats(method, uri, body), set(), f"{method} {uri} {body}")

    def test_techniques_and_snippets(self):
        hits = cr.scan_request("GET", "/item?id=1 UNION SELECT a FROM b", "")
        self.assertEqual(hits[0]["technique"], "T1190")
        self.assertIn("UNION SELECT", hits[0]["snippet"])
        self.assertLessEqual(len(hits[0]["snippet"]), 160)
        self.assertIsNone(cr.scan_request("GET", "/?q=<script>", "")[0]["technique"])                # XSS: no forced mapping
        self.assertEqual(cr.TECHNIQUES["web_shell"], "T1505.003")

    def test_tiers(self):
        hit = [{"rule_id": "x"}]
        self.assertTrue(cr.evidence_tier(True, hit).startswith("strong evidence"))
        self.assertTrue(cr.evidence_tier(False, hit).startswith("alert on content"))
        self.assertEqual(cr.evidence_tier(True, []), "flow anomaly only")
        self.assertEqual(cr.evidence_tier(None, []), "no alert")

    def test_ruleset_is_fingerprinted(self):
        self.assertEqual(cr.ruleset_sha256(), cr.ruleset_sha256())
        self.assertEqual(len(cr.ruleset_sha256()), 64)
        self.assertEqual(cr.RULESET_VERSION, "content-rules-v1")


def packet(src, sport, dst, dport, seq, payload):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(bytes(ip))
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def write_pcap(path, packets):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for i, p in enumerate(packets): w.writepkt(p, ts=1000 + i)


SQLI = b"GET /dvwa/sqli/?id=1%27+UNION+SELECT+user%2Cpassword+FROM+users--+ HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n"
BODY = b"cmd=127.0.0.1%3Bcat+%2Fetc%2Fpasswd"
POST = b"POST /dvwa/exec/ HTTP/1.1\r\nHost: 192.168.1.10\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + \
       str(len(BODY)).encode() + b"\r\n\r\n" + BODY
NORMAL = b"GET /index.html HTTP/1.1\r\nHost: example.local\r\n\r\n"
TLS = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.dir = Path(self.tmp.name)

    def tearDown(self): self.tmp.cleanup()

    def test_split_segments_pipelining_and_tls(self):
        pcap = self.dir / "a.pcap"
        half = len(POST) // 2
        write_pcap(pcap, [
            packet("10.0.0.2", 40000, "192.168.1.10", 80, 100, SQLI + NORMAL),                 # two pipelined requests
            packet("10.0.0.3", 40001, "192.168.1.10", 8080, 500, POST[:half]),                 # body split over segments
            packet("10.0.0.3", 40001, "192.168.1.10", 8080, 500, POST[:half]),                 # retransmission: dropped
            packet("10.0.0.3", 40001, "192.168.1.10", 8080, 500 + half, POST[half:]),
            packet("10.0.0.4", 40002, "192.168.1.10", 443, 1, TLS),
            packet("192.168.1.10", 80, "10.0.0.2", 40000, 1, b"HTTP/1.1 200 OK\r\n\r\n")])   # server reply ignored
        from collections import Counter
        stats = Counter()
        reqs = list(extract.iter_requests(pcap, "test", stats))
        self.assertEqual([r["method"] for r in reqs], ["GET", "GET", "POST"])
        self.assertEqual(reqs[2]["body"], BODY.decode())
        self.assertEqual(reqs[2]["dport"], 8080)
        self.assertEqual(stats["tls_client_hellos"], 1)
        self.assertEqual(stats["requests"], 3)

    def test_evaluation_end_to_end(self):
        benign, attack = self.dir / "benign.pcap", self.dir / "sqli.pcap"
        write_pcap(benign, [packet("10.0.0.5", 41000 + i, "1.2.3.4", 80, 1, NORMAL) for i in range(20)])
        write_pcap(attack, [packet("10.0.0.6", 42000, "192.168.1.10", 80, 1, SQLI + NORMAL)])
        out = self.dir / "out"
        evaluate.main(["--benign", str(benign), "--attack", f"SqlInjection={attack}", "--out", str(out)])
        summary = json.loads((out / "summary.json").read_text())
        b = summary["benign_false_positives"]
        self.assertEqual((b["requests"], b["requests_with_hit"]), (20, 0))
        sqli = next(c for c in summary["captures"] if c["label"] == "SqlInjection")
        self.assertEqual((sqli["requests"], sqli["requests_with_hit"]), (2, 1))        # background request counted, not hit
        self.assertEqual(sqli["requests_by_category"], {"sql_injection": 1})
        self.assertEqual(summary["ruleset_sha256"], cr.ruleset_sha256())
        self.assertTrue((out / "attack_SqlInjection_hits.jsonl").exists())
        self.assertIn("lower bounds on recall", (out / "summary.md").read_text())


class Packaging(unittest.TestCase):
    def test_dpkt_is_in_requirements(self):
        # bug: a teammate's fresh install lacked dpkt, so the content-check tests could not import
        req = (Path(__file__).resolve().parents[1] / "requirements.txt").read_text(encoding="utf-8").lower()
        self.assertRegex(req, r"(?m)^dpkt==")


class E2ETestTimeout(unittest.TestCase):
    def test_hung_suite_is_reported_as_fail_not_waited_on(self):
        # bug: e2e_check's test step had no timeout, and a teammate's run sat for two hours with no output
        import subprocess
        from unittest import mock
        import e2e_check
        results = []
        with mock.patch.object(e2e_check.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("x", 5, stderr="test_a ... ok" + chr(10) + "test_b ...")), \
             mock.patch.object(e2e_check, "check", side_effect=lambda ok, *a: results.append((ok, a))), \
             mock.patch.object(e2e_check, "section"):
            e2e_check.section_tests(timeout=5)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0][0])
        self.assertIn("timed out after 5 s", results[0][1][2])
        self.assertIn("test_b", results[0][1][2])


if __name__ == "__main__":
    unittest.main()
