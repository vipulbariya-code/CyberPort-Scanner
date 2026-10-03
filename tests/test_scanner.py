import socket
from unittest.mock import patch, MagicMock
import pytest

from scanner import (
    validate_target,
    validate_port_range,
    resolve_target,
    validate_resolved_target,
    PortScanner,
    ValidationError,
    get_service_name,
)


class TestTargetValidation:
    def test_valid_ipv4(self):
        assert validate_target("127.0.0.1") == "127.0.0.1"
        assert validate_target("192.168.1.100") == "192.168.1.100"
        assert validate_target("10.0.0.1") == "10.0.0.1"

    def test_valid_hostname(self):
        assert validate_target("localhost") == "localhost"
        assert validate_target("my-laptop.local") == "my-laptop.local"
        assert validate_target("scanme.nmap.org") == "scanme.nmap.org"

    def test_url_and_port_stripping(self):
        assert validate_target("http://192.168.1.1") == "192.168.1.1"
        assert validate_target("https://10.0.0.1:8080/dashboard") == "10.0.0.1"
        assert validate_target("localhost:5000") == "localhost"

    def test_empty_or_whitespace_target(self):
        with pytest.raises(ValidationError, match="required"):
            validate_target("")
        with pytest.raises(ValidationError, match="required"):
            validate_target("   ")
        with pytest.raises(ValidationError, match="required"):
            validate_target("http://")

    def test_invalid_ipv4_octets(self):
        with pytest.raises(ValidationError, match="not a valid IPv4"):
            validate_target("999.999.999.999")
        with pytest.raises(ValidationError, match="not a valid IPv4"):
            validate_target("192.168.1.300")

    def test_invalid_characters(self):
        with pytest.raises(ValidationError, match="valid IPv4 address or hostname"):
            validate_target("127.0.0.1; rm -rf /")
        with pytest.raises(ValidationError, match="valid IPv4 address or hostname"):
            validate_target("bad host name")


class TestPortRangeValidation:
    def test_valid_range(self):
        assert validate_port_range(1, 1024) == (1, 1024)
        assert validate_port_range("80", "443") == (80, 443)
        assert validate_port_range(22, 22) == (22, 22)

    def test_non_integer_ports(self):
        with pytest.raises(ValidationError, match="whole numbers"):
            validate_port_range("abc", 80)
        with pytest.raises(ValidationError, match="whole numbers"):
            validate_port_range(80, "xyz")

    def test_out_of_bounds_ports(self):
        with pytest.raises(ValidationError, match="between 1 and 65535"):
            validate_port_range(0, 100)
        with pytest.raises(ValidationError, match="between 1 and 65535"):
            validate_port_range(80, 70000)

    def test_reversed_range(self):
        with pytest.raises(ValidationError, match="less than or equal"):
            validate_port_range(100, 50)

    def test_range_too_large(self):
        with pytest.raises(ValidationError, match="too large"):
            validate_port_range(1, 2000, max_range=1024)


class TestTargetResolutionAndSafety:
    def test_localhost_resolution(self):
        ip = resolve_target("localhost")
        assert ip in ("127.0.0.1", "::1", "127.0.1.1")

    def test_nonexistent_host_resolution(self):
        with pytest.raises(ValidationError, match="Could not resolve host"):
            resolve_target("this-domain-definitely-does-not-exist-1234567.fake")

    def test_private_target_acceptance(self):
        assert validate_resolved_target("127.0.0.1", private_only=True) == "127.0.0.1"
        assert validate_resolved_target("192.168.1.1", private_only=True) == "192.168.1.1"
        assert validate_resolved_target("10.0.0.1", private_only=True) == "10.0.0.1"
        assert validate_resolved_target("172.16.0.1", private_only=True) == "172.16.0.1"

    def test_public_target_rejection(self):
        with pytest.raises(ValidationError, match="private-network or localhost"):
            validate_resolved_target("8.8.8.8", private_only=True)
        with pytest.raises(ValidationError, match="private-network or localhost"):
            validate_resolved_target("1.1.1.1", private_only=True)

    def test_unspecified_multicast_reserved_rejection(self):
        with pytest.raises(ValidationError, match="not allowed"):
            validate_resolved_target("0.0.0.0", private_only=False)
        with pytest.raises(ValidationError, match="not allowed"):
            validate_resolved_target("224.0.0.1", private_only=False)
        with pytest.raises(ValidationError, match="not allowed"):
            validate_resolved_target("255.255.255.255", private_only=False)


class TestPortScannerEngine:
    def test_service_name_lookup(self):
        assert get_service_name(80) == "HTTP"
        assert get_service_name(443) == "HTTPS"
        assert get_service_name(22) == "SSH"
        assert get_service_name(9999) == "Unknown"

    @patch("socket.socket")
    def test_scanner_run(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        # Port 80 opens (0), Port 81 closes (errno != 0)
        mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] == 80 else 111

        scanner = PortScanner(target_ip="127.0.0.1", start_port=80, end_port=81, timeout=0.1)
        results = scanner.run()

        assert results["total_scanned"] == 2
        assert len(results["open_ports"]) == 1
        assert results["open_ports"][0]["port"] == 80
        assert results["open_ports"][0]["service"] == "HTTP"
        assert results["closed_count"] == 1

    @patch("socket.socket")
    def test_all_scanned_ports_returned_with_open_and_closed(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        # Port 22: closed (111), Port 80: open (0), Port 443: open (0)
        mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] in (80, 443) else 111

        scanner = PortScanner(target_ip="127.0.0.1", start_port=22, end_port=443, timeout=0.1)
        results = scanner.run()

        # Check total scanned and full scanned_ports presence
        assert "scanned_ports" in results
        assert len(results["scanned_ports"]) == (443 - 22 + 1)
        assert len(results["open_ports"]) == 2

        # Verify open ports
        open_ports_list = [p["port"] for p in results["open_ports"]]
        assert open_ports_list == [80, 443]

        # Verify port 22 in scanned_ports
        port_22 = next(p for p in results["scanned_ports"] if p["port"] == 22)
        assert port_22["status"] == "CLOSED"
        assert port_22["state"] == "closed"
        assert port_22["service"] == "SSH"

        # Verify port 80 in scanned_ports
        port_80 = next(p for p in results["scanned_ports"] if p["port"] == 80)
        assert port_80["status"] == "OPEN"
        assert port_80["state"] == "open"
        assert port_80["service"] == "HTTP"

    @patch("socket.socket")
    def test_zero_open_ports_scan_displays_all_scanned_ports(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        # All ports closed
        mock_sock.connect_ex.return_value = 111

        scanner = PortScanner(target_ip="127.0.0.1", start_port=1, end_port=5, timeout=0.1)
        results = scanner.run()

        assert results["total_scanned"] == 5
        assert len(results["open_ports"]) == 0
        assert len(results["scanned_ports"]) == 5
        assert results["closed_count"] == 5
        for p in results["scanned_ports"]:
            assert p["status"] == "CLOSED"
            assert p["state"] == "closed"

    @patch("socket.socket")
    def test_filtered_and_error_handling(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        def mock_connect(addr):
            port = addr[1]
            if port == 80:
                return 0  # OPEN
            elif port == 22:
                return 111  # CLOSED (ECONNREFUSED)
            elif port == 23:
                return 110  # FILTERED (ETIMEDOUT)
            elif port == 25:
                raise socket.timeout("Timed out")  # FILTERED
            elif port == 53:
                raise Exception("Fatal connection failure")  # ERROR
            return 111

        mock_sock.connect_ex.side_effect = mock_connect

        scanner = PortScanner(target_ip="127.0.0.1", start_port=22, end_port=80, timeout=0.1)
        results = scanner.run()

        # Check port statuses
        scanned_dict = {p["port"]: p for p in results["scanned_ports"]}
        assert scanned_dict[80]["status"] == "OPEN"
        assert scanned_dict[22]["status"] == "CLOSED"
        assert scanned_dict[23]["status"] == "FILTERED"
        assert scanned_dict[25]["status"] == "FILTERED"
        assert scanned_dict[53]["status"] == "ERROR"
        assert scanned_dict[80]["service"] == "HTTP"
        assert scanned_dict[22]["service"] == "SSH"

    def test_scanner_cancellation(self):
        scanner = PortScanner(target_ip="127.0.0.1", start_port=1, end_port=100)
        scanner.cancel()
        results = scanner.run()
        # When cancelled before running, it returns immediately without completing all ports
        assert results["total_scanned"] < 100
