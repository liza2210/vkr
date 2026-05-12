from datetime import datetime, timezone

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import PcapReader

from app.core.enums import ArtifactType
from app.models import Artifact


class PcapParser:
    def parse_file(self, file_path: str, evidence_object_id: int) -> list[Artifact]:
        artifacts = []

        tcp_flows = {}
        udp_flows = {}

        with PcapReader(file_path) as packets:
            for packet_number, packet in enumerate(packets, start=1):
                try:
                    base = self._get_base_data(packet, packet_number)

                    if base is None:
                        continue

                    if packet.haslayer(TCP):
                        self._add_tcp_flow(packet, base, tcp_flows)

                        http_artifact = self._parse_http(
                            packet,
                            evidence_object_id,
                            base,
                        )

                        if http_artifact is not None:
                            artifacts.append(http_artifact)

                        tls_artifact = self._parse_tls_client_hello(
                            packet,
                            evidence_object_id,
                            base,
                        )

                        if tls_artifact is not None:
                            artifacts.append(tls_artifact)

                    if packet.haslayer(UDP):
                        self._add_udp_flow(packet, base, udp_flows)

                        dns_artifacts = self._parse_dns(
                            packet,
                            evidence_object_id,
                            base,
                        )

                        artifacts.extend(dns_artifacts)

                except Exception:
                    # Для MVP просто пропускаем пакет, если он не разобрался
                    continue

        for flow in tcp_flows.values():
            artifacts.append(self._make_tcp_flow_artifact(evidence_object_id, flow))

        for flow in udp_flows.values():
            artifacts.append(self._make_udp_flow_artifact(evidence_object_id, flow))

        return artifacts

    def _get_base_data(self, packet, packet_number: int) -> dict | None:
        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            ip_version = 4
        elif packet.haslayer(IPv6):
            ip = packet[IPv6]
            src_ip = ip.src
            dst_ip = ip.dst
            ip_version = 6
        else:
            return None

        src_port = None
        dst_port = None
        protocol = "ip"

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            protocol = "tcp"

        if packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            protocol = "udp"

        return {
            "packet_number": packet_number,
            "timestamp": self._packet_time(packet),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "ip_version": ip_version,
            "length_bytes": len(packet),
        }

    def _packet_time(self, packet) -> datetime:
        return datetime.fromtimestamp(float(packet.time), tz=timezone.utc)

    def _flow_key(self, base: dict):
        left = (base["src_ip"], base["src_port"])
        right = (base["dst_ip"], base["dst_port"])

        if str(left) <= str(right):
            return left, right

        return right, left

    def _add_tcp_flow(self, packet, base: dict, tcp_flows: dict):
        key = self._flow_key(base)

        if key not in tcp_flows:
            tcp_flows[key] = {
                "endpoint_a": key[0],
                "endpoint_b": key[1],
                "first_seen": base["timestamp"],
                "last_seen": base["timestamp"],
                "packet_count": 0,
                "bytes": 0,
                "packets_a_to_b": 0,
                "packets_b_to_a": 0,
                "bytes_a_to_b": 0,
                "bytes_b_to_a": 0,
                "from_syn": False,
                "from_fin": False,
                "from_rst": False,
                "client": None,
                "server": None,
            }

        flow = tcp_flows[key]
        flow["last_seen"] = base["timestamp"]
        flow["packet_count"] += 1
        flow["bytes"] += base["length_bytes"]

        current_direction = (
            (base["src_ip"], base["src_port"]),
            (base["dst_ip"], base["dst_port"]),
        )

        if current_direction[0] == flow["endpoint_a"]:
            flow["packets_a_to_b"] += 1
            flow["bytes_a_to_b"] += base["length_bytes"]
        else:
            flow["packets_b_to_a"] += 1
            flow["bytes_b_to_a"] += base["length_bytes"]

        tcp = packet[TCP]
        flags = int(tcp.flags)

        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)

        if syn and not ack:
            flow["from_syn"] = True
            flow["client"] = (base["src_ip"], base["src_port"])
            flow["server"] = (base["dst_ip"], base["dst_port"])

        if fin:
            flow["from_fin"] = True

        if rst:
            flow["from_rst"] = True

    def _make_tcp_flow_artifact(
        self,
        evidence_object_id: int,
        flow: dict,
    ) -> Artifact:
        client = flow["client"] or flow["endpoint_a"]
        server = flow["server"] or flow["endpoint_b"]

        duration = (flow["last_seen"] - flow["first_seen"]).total_seconds()

        return Artifact(
            id=None,
            evidence_object_id=evidence_object_id,
            artifact_type=ArtifactType.TCP_CONNECTION,
            timestamp=flow["first_seen"],
            timestamp_start=flow["first_seen"],
            timestamp_end=flow["last_seen"],
            title=(f"TCP flow {client[0]}:{client[1]} " f"<-> {server[0]}:{server[1]}"),
            raw_data_json={
                "first_seen": flow["first_seen"].isoformat(),
                "last_seen": flow["last_seen"].isoformat(),
            },
            parsed_data_json={
                "event": "tcp_connection",
                "src_ip": client[0],
                "dst_ip": server[0],
                "src_port": client[1],
                "dst_port": server[1],
                "protocol": "tcp",
                "packet_count": flow["packet_count"],
                "bytes": flow["bytes"],
                "first_seen": flow["first_seen"].isoformat(),
                "last_seen": flow["last_seen"].isoformat(),
                "duration_seconds": duration,
                "from_syn": flow["from_syn"],
                "observed_only": not flow["from_syn"],
                "from_fin": flow["from_fin"],
                "from_rst": flow["from_rst"],
                "packets_a_to_b": flow["packets_a_to_b"],
                "packets_b_to_a": flow["packets_b_to_a"],
                "bytes_a_to_b": flow["bytes_a_to_b"],
                "bytes_b_to_a": flow["bytes_b_to_a"],
            },
        )

    def _add_udp_flow(self, packet, base: dict, udp_flows: dict):
        key = (
            base["src_ip"],
            base["dst_ip"],
            base["src_port"],
            base["dst_port"],
        )

        if key not in udp_flows:
            udp_flows[key] = {
                "src_ip": base["src_ip"],
                "dst_ip": base["dst_ip"],
                "src_port": base["src_port"],
                "dst_port": base["dst_port"],
                "first_seen": base["timestamp"],
                "last_seen": base["timestamp"],
                "packet_count": 0,
                "bytes": 0,
            }

        flow = udp_flows[key]
        flow["last_seen"] = base["timestamp"]
        flow["packet_count"] += 1
        flow["bytes"] += base["length_bytes"]

    def _make_udp_flow_artifact(
        self,
        evidence_object_id: int,
        flow: dict,
    ) -> Artifact:
        duration = (flow["last_seen"] - flow["first_seen"]).total_seconds()

        return Artifact(
            id=None,
            evidence_object_id=evidence_object_id,
            artifact_type=ArtifactType.UDP_FLOW,
            timestamp=flow["first_seen"],
            timestamp_start=flow["first_seen"],
            timestamp_end=flow["last_seen"],
            title=(
                f"UDP flow {flow['src_ip']}:{flow['src_port']} "
                f"-> {flow['dst_ip']}:{flow['dst_port']}"
            ),
            raw_data_json={
                "first_seen": flow["first_seen"].isoformat(),
                "last_seen": flow["last_seen"].isoformat(),
            },
            parsed_data_json={
                "event": "udp_flow",
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "protocol": "udp",
                "packet_count": flow["packet_count"],
                "bytes": flow["bytes"],
                "first_seen": flow["first_seen"].isoformat(),
                "last_seen": flow["last_seen"].isoformat(),
                "duration_seconds": duration,
            },
        )

    def _get_dns_answers(self, dns) -> list[dict]:
        answers = []

        for i in range(dns.ancount):
            answer = dns.an[i]

            if not isinstance(answer, DNSRR):
                continue

            answers.append(
                {
                    "name": self._decode_dns_value(answer.rrname),
                    "type": self._dns_type_name(answer.type),
                    "value": self._decode_dns_value(answer.rdata),
                    "ttl": int(answer.ttl),
                }
            )

        return answers

    def _parse_dns(
        self,
        packet,
        evidence_object_id: int,
        base: dict,
    ) -> list[Artifact]:
        dns = self._get_dns_layer(packet)

        if dns is None:
            return []

        dns_protocol = self._get_dns_protocol(base)
        artifacts = []

        questions = self._get_dns_questions(dns)
        answers = self._get_dns_answers(dns)

        if dns.qr == 0:
            for question in questions:
                query_name = question["query_name"]
                query_type = question["query_type"]

                if query_name is None:
                    continue

                artifacts.append(
                    self._artifact(
                        evidence_object_id=evidence_object_id,
                        artifact_type=ArtifactType.DNS_QUERY,
                        title=f"DNS query: {query_name}",
                        base=base,
                        parsed_data={
                            "event": "dns_query",
                            "dns_protocol": dns_protocol,
                            "src_ip": base["src_ip"],
                            "dst_ip": base["dst_ip"],
                            "src_port": base["src_port"],
                            "dst_port": base["dst_port"],
                            "protocol": "udp",
                            "query_name": query_name,
                            "query_type": query_type,
                        },
                    )
                )

        if dns.qr == 1:
            query_name = None

            if questions:
                query_name = questions[0]["query_name"]

            response_name = query_name

            if response_name is None and answers:
                response_name = answers[0].get("name")

            if response_name is None and not answers:
                return artifacts

            artifacts.append(
                self._artifact(
                    evidence_object_id=evidence_object_id,
                    artifact_type=ArtifactType.DNS_RESPONSE,
                    title=f"DNS response: {response_name}",
                    base=base,
                    parsed_data={
                        "event": "dns_response",
                        "dns_protocol": dns_protocol,
                        "src_ip": base["src_ip"],
                        "dst_ip": base["dst_ip"],
                        "src_port": base["src_port"],
                        "dst_port": base["dst_port"],
                        "protocol": "udp",
                        "query_name": query_name,
                        "response_name": response_name,
                        "answers": answers,
                    },
                )
            )

        return artifacts

    def _get_dns_questions(self, dns) -> list[dict]:
        questions = []

        if dns.qd is None:
            return questions

        records = dns.qd

        if not isinstance(records, list):
            records = [records]

        for question in records:
            if not isinstance(question, DNSQR):
                continue

            query_name = self._decode_dns_value(question.qname)

            if query_name is None:
                continue

            questions.append(
                {
                    "query_name": query_name,
                    "query_type": self._dns_type_name(question.qtype),
                }
            )

        return questions

    def _get_dns_layer(self, packet):
        if packet.haslayer(DNS):
            return packet[DNS]

        if not packet.haslayer(UDP):
            return None

        udp = packet[UDP]
        ports = {int(udp.sport), int(udp.dport)}

        if not ports.intersection({53, 5353, 5355}):
            return None

        try:
            return DNS(bytes(udp.payload))
        except Exception:
            return None

    def _get_dns_protocol(self, base: dict) -> str:
        ports = {base["src_port"], base["dst_port"]}

        if 5353 in ports:
            return "mdns"

        if 5355 in ports:
            return "llmnr"

        if 53 in ports:
            return "dns"

        return "dns_like"

    def _parse_http(
        self,
        packet,
        evidence_object_id: int,
        base: dict,
    ) -> Artifact | None:
        if not packet.haslayer(Raw):
            return None

        payload = bytes(packet[Raw].load)

        methods = [
            b"GET ",
            b"POST ",
            b"PUT ",
            b"DELETE ",
            b"HEAD ",
            b"OPTIONS ",
            b"PATCH ",
        ]

        if not any(payload.startswith(method) for method in methods):
            return None

        text = payload.decode("iso-8859-1", errors="replace")
        lines = text.split("\r\n")

        if not lines:
            return None

        first_line = lines[0].split()

        if len(first_line) < 2:
            return None

        method = first_line[0]
        path = first_line[1]
        host = None

        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break

        return self._artifact(
            evidence_object_id=evidence_object_id,
            artifact_type=ArtifactType.HTTP_REQUEST_METADATA,
            title=f"HTTP request: {method} {host or ''}{path}",
            base=base,
            parsed_data={
                "event": "http_request_metadata",
                "src_ip": base["src_ip"],
                "dst_ip": base["dst_ip"],
                "src_port": base["src_port"],
                "dst_port": base["dst_port"],
                "protocol": "tcp",
                "method": method,
                "host": host,
                "path": path,
            },
        )

    def _parse_tls_client_hello(
        self,
        packet,
        evidence_object_id: int,
        base: dict,
    ) -> Artifact | None:
        if not packet.haslayer(Raw):
            return None

        payload = bytes(packet[Raw].load)
        tls_data = self._extract_tls_client_hello(payload)

        if tls_data is None:
            return None

        sni = tls_data.get("sni")

        return self._artifact(
            evidence_object_id=evidence_object_id,
            artifact_type=ArtifactType.TLS_CLIENT_HELLO_METADATA,
            title=f"TLS ClientHello: {sni or base['dst_ip']}",
            base=base,
            parsed_data={
                "event": "tls_client_hello_metadata",
                "src_ip": base["src_ip"],
                "dst_ip": base["dst_ip"],
                "src_port": base["src_port"],
                "dst_port": base["dst_port"],
                "protocol": "tcp",
                "sni": sni,
                "tls_version": tls_data.get("tls_version"),
            },
        )

    def _extract_tls_client_hello(self, data: bytes) -> dict | None:
        if len(data) < 5:
            return None

        if data[0] != 22:
            return None

        record_len = int.from_bytes(data[3:5], "big")

        if len(data) < 5 + record_len:
            return None

        pos = 5

        if data[pos] != 1:
            return None

        pos += 1

        if pos + 3 > len(data):
            return None

        handshake_len = int.from_bytes(data[pos : pos + 3], "big")
        pos += 3

        end = min(len(data), pos + handshake_len)

        if pos + 34 > end:
            return None

        client_version = data[pos : pos + 2]
        pos += 2

        pos += 32

        if pos + 1 > end:
            return None

        session_id_len = data[pos]
        pos += 1 + session_id_len

        if pos + 2 > end:
            return None

        cipher_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2 + cipher_len

        if pos + 1 > end:
            return None

        compression_len = data[pos]
        pos += 1 + compression_len

        if pos + 2 > end:
            return {
                "sni": None,
                "tls_version": self._tls_version_name(client_version),
            }

        extensions_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2

        extensions_end = min(end, pos + extensions_len)
        sni = None

        while pos + 4 <= extensions_end:
            ext_type = int.from_bytes(data[pos : pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4

            ext_data = data[pos : pos + ext_len]
            pos += ext_len

            if ext_type == 0:
                sni = self._parse_sni_extension(ext_data)

        return {
            "sni": sni,
            "tls_version": self._tls_version_name(client_version),
        }

    def _parse_sni_extension(self, data: bytes) -> str | None:
        if len(data) < 2:
            return None

        pos = 2

        while pos + 3 <= len(data):
            name_type = data[pos]
            name_len = int.from_bytes(data[pos + 1 : pos + 3], "big")
            pos += 3

            name = data[pos : pos + name_len]
            pos += name_len

            if name_type == 0:
                return name.decode("utf-8", errors="replace")

        return None

    def _tls_version_name(self, version_bytes: bytes) -> str | None:
        versions = {
            b"\x03\x01": "TLS 1.0",
            b"\x03\x02": "TLS 1.1",
            b"\x03\x03": "TLS 1.2",
            b"\x03\x04": "TLS 1.3",
        }

        return versions.get(version_bytes, version_bytes.hex())

    def _artifact(
        self,
        evidence_object_id: int,
        artifact_type: ArtifactType,
        title: str,
        base: dict,
        parsed_data: dict,
    ) -> Artifact:
        return Artifact(
            id=None,
            evidence_object_id=evidence_object_id,
            artifact_type=artifact_type,
            timestamp=base["timestamp"],
            timestamp_start=base["timestamp"],
            timestamp_end=None,
            title=title,
            raw_data_json={
                "packet_number": base["packet_number"],
                "timestamp": base["timestamp"].isoformat(),
                "length_bytes": base["length_bytes"],
            },
            parsed_data_json=parsed_data,
        )

    def _decode_dns_value(self, value):
        if value is None:
            return None

        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace").rstrip(".")

        return str(value).rstrip(".")

    def _dns_type_name(self, value) -> str:
        types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
        }

        return types.get(int(value), str(value))
