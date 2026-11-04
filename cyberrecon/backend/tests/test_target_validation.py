import pytest

from app.security.ip_policy import IPPolicy, block_reason, parse_ip
from app.security.target import TargetError, host_in_allowlist, parse_target, same_site


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "https://example.com/"),
        ("  Example.COM  ", "https://example.com/"),
        ("http://example.com", "http://example.com/"),
        ("HTTP://Example.COM:80/a/b?x=1#frag", "http://example.com/a/b?x=1"),
        ("https://example.com:443/", "https://example.com/"),
        ("https://example.com:8443/p", "https://example.com:8443/p"),
        ("example.com/path", "https://example.com/path"),
        ("https://sub.example.co.uk./", "https://sub.example.co.uk/"),
        ("bücher.de", "https://xn--bcher-kva.de/"),
        ("http://93.184.216.34/", "http://93.184.216.34/"),
        ("https://[2606:4700:4700::1111]/", "https://[2606:4700:4700::1111]/"),
    ],
)
def test_valid_targets_are_normalised(raw, expected):
    assert parse_target(raw).url == expected


@pytest.mark.parametrize(
    "raw,code",
    [
        ("", "empty_target"),
        ("   ", "empty_target"),
        ("file:///etc/passwd", "unsupported_scheme"),
        ("ftp://example.com/", "unsupported_scheme"),
        ("javascript:alert(1)", "unsupported_scheme"),
        ("data:text/html,<script>", "unsupported_scheme"),
        ("gopher://example.com", "unsupported_scheme"),
        ("http://user:pass@example.com/", "credentials_in_url"),
        ("http://example.com@evil.com/", "credentials_in_url"),
        ("http://127.0.0.1/", "blocked_address"),
        ("http://127.1/", "ambiguous_ip"),
        ("http://2130706433/", "ambiguous_ip"),
        ("http://0x7f.0.0.1/", "ambiguous_ip"),
        ("http://0177.0.0.1/", "ambiguous_ip"),
        ("http://[::1]/", "blocked_address"),
        ("http://[::ffff:127.0.0.1]/", "blocked_address"),
        ("http://[::ffff:7f00:1]/", "blocked_address"),
        ("http://169.254.169.254/latest/meta-data/", "blocked_address"),
        ("http://10.0.0.5/", "blocked_address"),
        ("http://172.16.4.4/", "blocked_address"),
        ("http://192.168.1.1/", "blocked_address"),
        ("http://100.64.0.1/", "blocked_address"),
        ("http://0.0.0.0/", "blocked_address"),
        ("http://224.0.0.1/", "blocked_address"),
        ("http://[fe80::1]/", "blocked_address"),
        ("http://[fd00::1]/", "blocked_address"),
        ("http://localhost/", "non_public_name"),
        ("http://intranet/", "non_public_name"),
        ("http://printer.local/", "non_public_name"),
        ("http://svc.internal/", "non_public_name"),
        ("http://example.com:22/", "port_not_allowed"),
        ("http://example.com:6379/", "port_not_allowed"),
        ("http://exa mple.com/", "invalid_characters"),
        ("http://example.com\\@evil.com/", "invalid_characters"),
        ("http://-bad-.example.com/", "invalid_host"),
        ("http://" + "a" * 70 + ".com/", "invalid_host"),
        ("http://example.com/" + "a" * 3000, "too_long"),
    ],
)
def test_prohibited_targets_are_rejected(raw, code):
    with pytest.raises(TargetError) as exc:
        parse_target(raw)
    assert exc.value.code == code, exc.value.message


def test_control_characters_rejected():
    with pytest.raises(TargetError):
        parse_target("http://example.com/\r\nHost: evil")


def test_allowlist_enforced_for_subdomains_only():
    allow = ["example.com"]
    assert parse_target("https://example.com", allowlist=allow)
    assert parse_target("https://app.example.com", allowlist=allow)
    with pytest.raises(TargetError) as exc:
        parse_target("https://badexample.com", allowlist=allow)
    assert exc.value.code == "out_of_scope"
    assert host_in_allowlist("anything.org", [])


def test_same_site_scope():
    assert same_site("example.com", "www.example.com")
    assert same_site("app.example.com", "example.com")
    assert not same_site("example.com", "evil-example.com")
    assert not same_site("example.com", "example.com.evil.net")


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fe80::1", "::ffff:10.0.0.1", "100.100.100.200", "2002:7f00:1::1", "64:ff9b::7f00:1"],
)
def test_blocked_ips(ip):
    assert block_reason(parse_ip(ip)) is not None
    assert not IPPolicy().is_allowed(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert IPPolicy().is_allowed(ip)
