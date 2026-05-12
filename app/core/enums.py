from enum import Enum


class InvestigationStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    ARCHIVED = "archived"


class EvidenceSourceType(str, Enum):
    LOG = "log"
    PCAP = "pcap"
    DIRECTORY = "directory"


class EvidenceSourceStatus(str, Enum):
    PENDING = "pending"
    COLLECTING = "collecting"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class EvidenceObjectType(str, Enum):
    FILE = "file"
    LOG = "log"
    PCAP = "pcap"


class ArtifactType(str, Enum):
    # logs
    LOG_ENTRY = "log_entry"
    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCESS = "login_success"
    PRIVILEGE_EVENT = "privilege_event"
    SERVICE_EVENT = "service_event"

    # pcap
    DNS_QUERY = "dns_query"
    DNS_RESPONSE = "dns_response"
    TCP_CONNECTION = "tcp_connection"
    UDP_FLOW = "udp_flow"
    HTTP_REQUEST_METADATA = "http_request_metadata"
    TLS_CLIENT_HELLO_METADATA = "tls_client_hello_metadata"

    # files
    FILE_DISCOVERED = "file_discovered"
    FILE_METADATA = "file_metadata"
    FILE_HASH_COMPUTED = "file_hash_computed"
    FILE_MODIFIED_MARKER = "file_modified_marker"
