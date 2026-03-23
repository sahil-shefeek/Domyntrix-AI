import pytest
from xai_translator import translate, FEATURE_LABELS

@pytest.fixture
def benign_profile():
    return {
        "length": 10, "n_ns": 4, "n_vowels": 2, "life_time": 11322,
        "n_vowel_chars": 4, "n_constant_chars": 5, "n_nums": 0,
        "n_other_chars": 0, "entropy": 2.64, "n_mx": 1,
        "ns_similarity": 0.93, "n_countries": 1, "n_labels": 353
    }

class TestTranslateOutputSchema:
    def test_schema_structure(self, benign_profile):
        results = translate(benign_profile)
        assert isinstance(results, list)
        for item in results:
            assert isinstance(item, dict)
            assert set(item.keys()) == {"feature", "label", "value", "verdict", "severity"}
            assert item["label"] == FEATURE_LABELS[item["feature"]]
            assert item["verdict"] != "" or item["value"] is None

    def test_output_length(self, benign_profile):
        results = translate(benign_profile)
        # Assuming all features in benign_profile are in FEATURE_LABELS
        expected_len = sum(1 for k in benign_profile if k in FEATURE_LABELS)
        assert len(results) == expected_len

class TestSeveritySortOrder:
    def test_sort_order(self):
        # Create a profile that triggers all severities
        mixed_profile = {
            "length": 21,        # high
            "n_ns": 1,          # medium
            "n_vowels": 3,      # safe
            "n_nums": None      # neutral
        }
        results = translate(mixed_profile)
        severities = [r["severity"] for r in results]
        
        # Priority: high > medium > safe > neutral
        rank = {"high": 0, "medium": 1, "safe": 2, "neutral": 3}
        sorted_severities = sorted(severities, key=lambda s: rank[s])
        
        assert severities == sorted_severities

class TestFeatureBranches:
    @pytest.mark.parametrize("feature, value, expected_severity", [
        ("length", 21, "high"),
        ("length", 20, "medium"),
        ("length", 12, "safe"),
        ("length", 13, "medium"),
        ("n_ns", 0, "high"),
        ("n_ns", 1, "medium"),
        ("n_ns", 3, "safe"),
        ("n_vowels", 5, "high"),
        ("n_vowels", 4, "medium"),
        ("n_vowels", 3, "safe"),
        ("life_time", 365, "high"),
        ("life_time", 366, "medium"),
        ("life_time", 2000, "safe"),
        ("n_vowel_chars", 8, "high"),
        ("n_vowel_chars", 5, "medium"),
        ("n_vowel_chars", 4, "safe"),
        ("n_constant_chars", 12, "high"),
        ("n_constant_chars", 8, "medium"),
        ("n_constant_chars", 6, "safe"),
        ("n_nums", 2, "high"),
        ("n_nums", 1, "medium"),
        ("n_nums", 0, "safe"),
        ("n_other_chars", 1, "high"),
        ("n_other_chars", 0, "safe"),
        ("entropy", 3.8, "high"),
        ("entropy", 3.1, "medium"),
        ("entropy", 2.8, "safe"),
        ("n_mx", 0, "high"),
        ("n_mx", 1, "medium"),
        ("n_mx", 2, "safe"),
        ("ns_similarity", 0.5, "high"),
        ("ns_similarity", 0.7, "medium"),
        ("ns_similarity", 0.9, "safe"),
        ("n_countries", 3, "high"),
        ("n_countries", 2, "medium"),
        ("n_countries", 1, "safe"),
        ("n_labels", 0, "high"),
        ("n_labels", 100, "medium"),
        ("n_labels", 200, "safe"),
    ])
    def test_thresholds(self, feature, value, expected_severity):
        results = translate({feature: value})
        assert len(results) == 1
        assert results[0]["severity"] == expected_severity
        assert results[0]["verdict"] != ""

class TestNullAndMissingInputs:
    def test_null_value(self):
        results = translate({"length": None})
        assert len(results) == 1
        assert results[0]["severity"] == "neutral"
        assert results[0]["verdict"] == "Data unavailable"

    def test_mixed_null_and_valid(self):
        results = translate({"length": None, "n_ns": 0})
        assert len(results) == 2
        
        length_res = next(r for r in results if r["feature"] == "length")
        n_ns_res = next(r for r in results if r["feature"] == "n_ns")
        
        assert length_res["severity"] == "neutral"
        assert n_ns_res["severity"] == "high"

    def test_empty_input(self):
        assert translate({}) == []

    def test_unknown_feature(self):
        assert translate({"unknown_feature": 42}) == []

    def test_mixed_valid_and_invalid_keys(self):
        results = translate({"length": 10, "bogus": 999})
        assert len(results) == 1
        assert results[0]["feature"] == "length"

class TestMadonnaProfiles:
    def test_malicious_profile(self):
        malicious_profile = {
            "length": 18, "n_ns": 2, "n_vowels": 4, "life_time": 365,
            "n_vowel_chars": 6, "n_constant_chars": 12, "n_nums": 0,
            "n_other_chars": 0, "entropy": 3.68, "n_mx": 5,
            "ns_similarity": 1.0, "n_countries": 2, "n_labels": 276
        }
        results = translate(malicious_profile)
        
        high_items = [r for r in results if r["severity"] == "high"]
        assert len(high_items) >= 2
        
        # Verify specific high severity triggers
        life_time_item = next(r for r in results if r["feature"] == "life_time")
        n_constant_chars_item = next(r for r in results if r["feature"] == "n_constant_chars")
        assert life_time_item["severity"] == "high"
        assert n_constant_chars_item["severity"] == "high"
        
        assert results[0]["severity"] == "high"
        assert len(results) == 13

    def test_benign_profile(self, benign_profile):
        results = translate(benign_profile)
        
        high_items = [r for r in results if r["severity"] == "high"]
        assert len(high_items) == 0
        assert len(results) == 13
        assert results[-1]["severity"] in {"safe", "neutral"}

    def test_fp_profile(self):
        fp_profile = {
            "length": 12, "n_ns": 2, "n_vowels": 2, "life_time": 365,
            "n_vowel_chars": 2, "n_constant_chars": 9, "n_nums": 0,
            "n_other_chars": 0, "entropy": 3.2516, "n_mx": 1,
            "ns_similarity": 1.0, "n_countries": 1, "n_labels": 126
        }
        results = translate(fp_profile)
        
        life_time_item = next(r for r in results if r["feature"] == "life_time")
        assert life_time_item["severity"] == "high"
        
        high_items = [r for r in results if r["severity"] == "high"]
        assert len(high_items) >= 1

def test_idempotency(benign_profile):
    res1 = translate(benign_profile)
    res2 = translate(benign_profile)
    assert res1 == res2
