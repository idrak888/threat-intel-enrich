"""Tests for enricher.utils.indicators — indicator type auto-detection."""

import pytest

from enricher.core.models import IndicatorType
from enricher.utils.indicators import Indicator, InvalidIndicatorError, detect


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------
class TestIPv4:
    def test_basic(self):
        ind = detect("8.8.8.8")
        assert ind == Indicator(value="8.8.8.8", type=IndicatorType.IP)

    def test_leading_trailing_whitespace(self):
        ind = detect("  192.168.1.1  ")
        assert ind.value == "192.168.1.1"
        assert ind.type == IndicatorType.IP

    def test_all_zeros(self):
        assert detect("0.0.0.0").type == IndicatorType.IP

    def test_broadcast(self):
        assert detect("255.255.255.255").type == IndicatorType.IP

    def test_tor_exit_node(self):
        assert detect("185.220.101.34").type == IndicatorType.IP

    @pytest.mark.parametrize(
        "bad",
        [
            "256.0.0.1",
            "1.2.3",
            "1.2.3.4.5",
            "1.2.3.999",
            "01.02.03.04",  # leading zeros are invalid per strict regex
        ],
    )
    def test_invalid_ipv4(self, bad):
        with pytest.raises(InvalidIndicatorError):
            detect(bad)


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------
class TestIPv6:
    def test_full_form(self):
        ind = detect("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert ind.type == IndicatorType.IP
        # ipaddress normalises to canonical compressed form
        assert ind.value == "2001:db8:85a3::8a2e:370:7334"

    def test_compressed_loopback(self):
        ind = detect("::1")
        assert ind.type == IndicatorType.IP

    def test_compressed_middle(self):
        ind = detect("2001:db8::1")
        assert ind.type == IndicatorType.IP

    def test_value_lowercased(self):
        ind = detect("2001:DB8::1")
        assert ind.value == "2001:db8::1"

    def test_all_zeros(self):
        assert detect("::").type == IndicatorType.IP


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------
class TestDomain:
    def test_simple(self):
        ind = detect("example.com")
        assert ind == Indicator(value="example.com", type=IndicatorType.DOMAIN)

    def test_subdomain(self):
        ind = detect("mail.google.com")
        assert ind.type == IndicatorType.DOMAIN

    def test_deep_subdomain(self):
        assert detect("a.b.c.evil.io").type == IndicatorType.DOMAIN

    def test_uppercase_normalised(self):
        ind = detect("Example.COM")
        assert ind.value == "example.com"
        assert ind.type == IndicatorType.DOMAIN

    def test_hyphen_in_label(self):
        assert detect("my-site.example.org").type == IndicatorType.DOMAIN

    def test_numeric_label(self):
        # e.g. "3com.com" is a valid domain
        assert detect("3com.com").type == IndicatorType.DOMAIN

    @pytest.mark.parametrize(
        "bad",
        [
            "notadomain",          # no dot
            "-bad.com",           # label starts with hyphen
            "bad-.com",           # label ends with hyphen
            "has space.com",      # contains space
            "foo.c",              # TLD too short (1 char)
        ],
    )
    def test_invalid_domains(self, bad):
        with pytest.raises(InvalidIndicatorError):
            detect(bad)


# ---------------------------------------------------------------------------
# MD5
# ---------------------------------------------------------------------------
class TestMD5:
    def test_lowercase(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        ind = detect(h)
        assert ind == Indicator(value=h, type=IndicatorType.HASH_MD5)

    def test_uppercase_normalised(self):
        h = "D41D8CD98F00B204E9800998ECF8427E"
        ind = detect(h)
        assert ind.type == IndicatorType.HASH_MD5
        assert ind.value == h.lower()

    def test_mixed_case(self):
        h = "D41d8CD98f00B204e9800998ECf8427e"
        assert detect(h).type == IndicatorType.HASH_MD5

    def test_wrong_length_not_md5(self):
        # 31 chars — too short for MD5 but also not SHA1/SHA256 → domain check fails → error
        with pytest.raises(InvalidIndicatorError):
            detect("d41d8cd98f00b204e9800998ecf842")


# ---------------------------------------------------------------------------
# SHA1
# ---------------------------------------------------------------------------
class TestSHA1:
    def test_basic(self):
        h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ind = detect(h)
        assert ind == Indicator(value=h, type=IndicatorType.HASH_SHA1)

    def test_uppercase_normalised(self):
        h = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        ind = detect(h)
        assert ind.value == h.lower()
        assert ind.type == IndicatorType.HASH_SHA1


# ---------------------------------------------------------------------------
# SHA256
# ---------------------------------------------------------------------------
class TestSHA256:
    def test_basic(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ind = detect(h)
        assert ind == Indicator(value=h, type=IndicatorType.HASH_SHA256)

    def test_uppercase_normalised(self):
        h = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        ind = detect(h)
        assert ind.value == h.lower()
        assert ind.type == IndicatorType.HASH_SHA256


# ---------------------------------------------------------------------------
# Edge / error cases
# ---------------------------------------------------------------------------
class TestEdgeCases:
    def test_empty_string(self):
        with pytest.raises(InvalidIndicatorError):
            detect("")

    def test_only_whitespace(self):
        with pytest.raises(InvalidIndicatorError):
            detect("   ")

    def test_random_garbage(self):
        with pytest.raises(InvalidIndicatorError):
            detect("not-an-indicator!!!")

    def test_url_not_accepted(self):
        with pytest.raises(InvalidIndicatorError):
            detect("http://example.com/path")

    def test_ip_with_port_not_accepted(self):
        with pytest.raises(InvalidIndicatorError):
            detect("8.8.8.8:53")

    def test_hash_priority_over_domain(self):
        """A 32-char hex string must be treated as MD5, not a domain."""
        h = "aabbccddeeff00112233445566778899"
        assert detect(h).type == IndicatorType.HASH_MD5

    def test_indicator_is_frozen(self):
        ind = detect("8.8.8.8")
        with pytest.raises((AttributeError, TypeError)):
            ind.value = "1.2.3.4"  # type: ignore[misc]
