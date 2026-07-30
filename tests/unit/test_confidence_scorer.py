from sentinel.findings.scorer import severity_from_score


class TestSeverityFromScore:

    def test_critical_threshold(self):
        assert severity_from_score(80) == "Critical"
        assert severity_from_score(100) == "Critical"

    def test_high_threshold(self):
        assert severity_from_score(60) == "High"
        assert severity_from_score(79) == "High"

    def test_medium_threshold(self):
        assert severity_from_score(40) == "Medium"
        assert severity_from_score(59) == "Medium"

    def test_low_threshold(self):
        assert severity_from_score(0) == "Low"
        assert severity_from_score(39) == "Low"
