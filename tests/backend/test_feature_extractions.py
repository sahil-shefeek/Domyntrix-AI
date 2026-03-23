import pytest
import dns.resolver
import dns.exception
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta
import feature_extractions

# Module-level fixture to mock DNS resolver
@pytest.fixture(autouse=True)
def mock_dns():
    with patch.object(dns.resolver.Resolver, "resolve") as mock_resolve:
        # Default behavior: raise NoAnswer
        mock_resolve.side_effect = dns.resolver.NoAnswer
        yield mock_resolve

def create_mock_answer(records, ttl=300):
    mock_answer = MagicMock()
    mock_answer.__iter__.return_value = records
    mock_answer.rrset = MagicMock()
    mock_answer.rrset.ttl = ttl
    return mock_answer

class TestTextBasedFeatures:
    @pytest.mark.asyncio
    async def test_google_com_text_features(self):
        # google.com (length 10)
        # We need to mock DNS, WHOIS, and get_html to avoid network calls
        with patch("feature_extractions.whois.whois") as mock_whois, \
             patch("feature_extractions.get_html", new_callable=AsyncMock) as mock_get_html, \
             patch("feature_extractions.Reader"):
            
            mock_get_html.return_value = None
            # Return None for dates to ensure numeric 0
            mock_whois.return_value = MagicMock(expiration_date=None, creation_date=None)
            
            features = await feature_extractions.extract_features("google.com")
            
            assert features[0] == 10  # length
            assert features[2] == 2   # n_vowels (o, e)
            assert features[4] == 4   # n_vowel_chars (o, o, e, o)
            assert features[5] == 5   # n_constant_chars (g, g, l, c, m)
            assert features[6] == 0   # n_nums
            assert features[7] == 0   # n_other_chars
            assert features[8] > 0    # entropy

    @pytest.mark.asyncio
    async def test_chromnius_download_text_features(self):
        # chromnius.download (18 chars)
        with patch("feature_extractions.whois.whois") as mock_whois, \
             patch("feature_extractions.get_html", new_callable=AsyncMock) as mock_get_html, \
             patch("feature_extractions.Reader"):
            
            mock_get_html.return_value = None
            mock_whois.return_value = MagicMock(expiration_date=None, creation_date=None)
            
            features = await feature_extractions.extract_features("chromnius.download")
            assert features[0] == 18
            assert features[6] == 0

class TestDnsFeatures:
    @pytest.mark.asyncio
    async def test_multiple_ns_records(self, mock_dns):
        # Mock 4 unique NS records
        records = []
        for i in range(4):
            mock_ns = MagicMock()
            mock_ns.__str__.return_value = f"ns{i}.example.com"
            records.append(mock_ns)
        
        # Side effect for query type "NS"
        def side_effect(domain, _type):
            if _type == "NS":
                return create_mock_answer(records)
            raise dns.resolver.NoAnswer
        
        mock_dns.side_effect = side_effect
        
        with patch("feature_extractions.whois.whois") as mock_whois, \
             patch("feature_extractions.get_html", new_callable=AsyncMock) as mock_get_html, \
             patch("feature_extractions.Reader"):
            
            mock_whois.return_value = MagicMock(expiration_date=None, creation_date=None)
            features = await feature_extractions.extract_features("example.com")
            assert features[1] == 4  # n_ns

    @pytest.mark.asyncio
    async def test_no_ns_records_nxdomain(self, mock_dns):
        mock_dns.side_effect = dns.resolver.NXDOMAIN
        
        with patch("feature_extractions.whois.whois") as mock_whois, \
             patch("feature_extractions.get_html", new_callable=AsyncMock), \
             patch("feature_extractions.Reader"):
            
            mock_whois.return_value = MagicMock(expiration_date=None, creation_date=None)
            features = await feature_extractions.extract_features("nonexistent.com")
            assert features[1] == 0  # n_ns

    @pytest.mark.asyncio
    async def test_resolver_timeout(self, mock_dns):
        mock_dns.side_effect = dns.exception.Timeout
        
        with patch("feature_extractions.whois.whois") as mock_whois, \
             patch("feature_extractions.get_html", new_callable=AsyncMock), \
             patch("feature_extractions.Reader"):
            
            mock_whois.return_value = MagicMock(expiration_date=None, creation_date=None)
            features = await feature_extractions.extract_features("timeout.com")
            assert len(features) == 13
            assert isinstance(features[1], int)

    @pytest.mark.asyncio
    async def test_ns_similarity_identical(self, mock_dns):
        # Mock 2 same NS records (but separate objects with same string representation)
        rec1 = MagicMock()
        rec1.__str__.return_value = "ns1.identical.com"
        rec2 = MagicMock()
        rec2.__str__.return_value = "ns1.identical.com"
        
        def side_effect(domain, _type):
            if _type == "NS":
                return create_mock_answer([rec1, rec2])
            if _type == "A":
                mock_ip = MagicMock()
                mock_ip.__str__.return_value = "1.2.3.4"
                return create_mock_answer([mock_ip])
            return create_mock_answer([])
            
        mock_dns.side_effect = side_effect
        
        with patch("feature_extractions.whois.whois") as mock_whois, \
             patch("feature_extractions.get_html", new_callable=AsyncMock), \
             patch("feature_extractions.Reader"):
            
            mock_whois.return_value = MagicMock(expiration_date=None, creation_date=None)
            features = await feature_extractions.extract_features("identical.com")
            # names = {"ns1.identical.com"} -> len is 1
            assert features[1] == 1
            # 1 NS record -> ns_similarity returns 1.0 (else block)
            assert features[10] == 1.0

class TestLifeTimeFeature:
    def test_normal_whois_response(self):
        with patch("feature_extractions.whois.whois") as mock_whois:
            now = datetime.now()
            mock_whois.return_value = MagicMock(
                expiration_date=now + timedelta(days=3650),
                creation_date=now
            )
            life_time = feature_extractions.get_life_time("example.com")
            assert life_time == pytest.approx(3650, abs=1)

    def test_list_type_whois_dates(self):
        with patch("feature_extractions.whois.whois") as mock_whois:
            now = datetime.now()
            mock_whois.return_value = MagicMock(
                expiration_date=[now + timedelta(days=100)],
                creation_date=[now]
            )
            life_time = feature_extractions.get_life_time("example.com")
            assert life_time == pytest.approx(100, abs=1)

    def test_whois_returns_none(self):
        with patch("feature_extractions.whois.whois") as mock_whois:
            mock_whois.return_value = MagicMock(
                expiration_date=None,
                creation_date=None
            )
            life_time = feature_extractions.get_life_time("example.com")
            assert life_time == 0

class TestNLabelsFeature:
    @pytest.mark.asyncio
    async def test_valid_html_page(self):
        with patch("feature_extractions.get_html", new_callable=AsyncMock) as mock_get_html:
            mock_get_html.return_value = b"<html><body><p><a><div></div></a></p></body></html>"
            n_labels = await feature_extractions.get_n_labels("example.com", "example.com")
            # tags: html, body, p, a, div -> 5 tags
            assert n_labels == 5

    @pytest.mark.asyncio
    async def test_empty_none_response(self):
        with patch("feature_extractions.get_html", new_callable=AsyncMock) as mock_get_html:
            mock_get_html.return_value = None
            n_labels = await feature_extractions.get_n_labels("example.com", "example.com")
            assert n_labels == 0

class TestFullExtractFeatures:
    @pytest.mark.asyncio
    async def test_feature_array_shape(self):
        with patch("feature_extractions.whois.whois") as mock_whois, \
             patch("feature_extractions.get_html", new_callable=AsyncMock), \
             patch("feature_extractions.Reader"):
            
            mock_whois.return_value = MagicMock(expiration_date=None, creation_date=None)
            features = await feature_extractions.extract_features("example.com")
            assert len(features) == 13

    @pytest.mark.asyncio
    async def test_all_values_are_numeric(self):
        with patch("feature_extractions.whois.whois") as mock_whois, \
             patch("feature_extractions.get_html", new_callable=AsyncMock), \
             patch("feature_extractions.Reader"):
            
            mock_whois.return_value = MagicMock(expiration_date=None, creation_date=None)
            features = await feature_extractions.extract_features("example.com")
            for val in features:
                assert isinstance(val, (int, float))

    @pytest.mark.asyncio
    async def test_google_com_benign_profile(self, mock_dns):
        # MADONNA paper Table 8: n_ns=4, life_time=11322, n_mx=1, n_labels=353
        
        def dns_side_effect(domain, _type):
            if _type == "NS":
                records = []
                for i in range(4):
                    mock_ns = MagicMock()
                    mock_ns.__str__.return_value = f"ns{i}.google.com"
                    records.append(mock_ns)
                return create_mock_answer(records)
            if _type == "MX":
                mock_mx = MagicMock()
                mock_mx.__str__.return_value = "mx1.google.com"
                return create_mock_answer([mock_mx])
            if _type == "A":
                return create_mock_answer([])
            return []
            
        mock_dns.side_effect = dns_side_effect
        
        with patch("feature_extractions.whois.whois") as mock_whois, \
             patch("feature_extractions.get_html", new_callable=AsyncMock) as mock_get_html, \
             patch("feature_extractions.Reader") as mock_reader_class:
            
            # Setup WHOIS
            mock_whois.return_value = MagicMock(
                expiration_date=datetime(2030, 1, 1),
                creation_date=datetime(2030, 1, 1) - timedelta(days=11322)
            )
            
            # Setup HTML labels
            mock_get_html.return_value = b"<a></a>" * 353
            
            # Setup GeoIP
            mock_reader_instance = mock_reader_class.return_value
            mock_country = MagicMock()
            mock_country.iso_code = "US"
            mock_city_resp = MagicMock()
            mock_city_resp.country = mock_country
            mock_reader_instance.city.return_value = mock_city_resp
            
            features = await feature_extractions.extract_features("google.com")
            
            assert features[0] == 10       # length
            assert features[1] == 4        # n_ns
            assert features[3] == 11322    # life_time
            assert features[9] == 1        # n_mx
            assert features[12] == 353     # n_labels
            # Check text-based features
            assert features[2] == 2        # n_vowels
            assert features[4] == 4        # n_vowel_chars
            assert features[5] == 5        # n_constant_chars
