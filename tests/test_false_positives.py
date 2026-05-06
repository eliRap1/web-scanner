"""
Tests for false positive detection in XSS scanning.

Verifies that:
- Search result reflections are NOT flagged as XSS
- Actual XSS (payload in script tag, event handler) IS flagged
- Encoded reflections are NOT flagged
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from scanner.vulnerability_tester import VulnerabilityTester


@pytest.fixture
def tester():
    return VulnerabilityTester(min_confidence=0.7, confirm_findings=False)


class TestSearchReflectionDetection:
    """Test that _is_search_reflection catches common false positive patterns."""

    def test_no_results_for_payload(self, tester):
        html = '<html><body><p>No results for "<script>alert(1)</script>"</p></body></html>'
        assert tester._is_search_reflection(html, "<script>alert(1)</script>") is True

    def test_your_search_for_payload(self, tester):
        html = '<div>Your search for "<script>alert(1)</script>" did not match any results</div>'
        assert tester._is_search_reflection(html, "<script>alert(1)</script>") is True

    def test_search_results_for(self, tester):
        html = '<h2>Search results for "<img onerror=alert(1)>"</h2><p>Nothing found</p>'
        assert tester._is_search_reflection(html, '<img onerror=alert(1)>') is True

    def test_did_you_mean(self, tester):
        html = '<p>Did you mean something? You searched for: <script>alert(1)</script></p>'
        assert tester._is_search_reflection(html, "<script>alert(1)</script>") is True

    def test_zero_results(self, tester):
        html = '<span>0 results for <script>alert(1)</script></span>'
        assert tester._is_search_reflection(html, "<script>alert(1)</script>") is True

    def test_showing_results_for(self, tester):
        html = '<p>Showing results for "<script>alert(1)</script>"</p>'
        assert tester._is_search_reflection(html, "<script>alert(1)</script>") is True

    def test_nothing_found(self, tester):
        html = '<div>Nothing found for "<script>alert(1)</script>". Try again.</div>'
        assert tester._is_search_reflection(html, "<script>alert(1)</script>") is True

    def test_query_colon_pattern(self, tester):
        html = '<div>Query: <script>alert(1)</script> returned no data</div>'
        assert tester._is_search_reflection(html, "<script>alert(1)</script>") is True

    def test_not_search_in_script_tag(self, tester):
        """Payload inside actual <script> tag is NOT a search reflection."""
        html = '<html><script>var x = "<script>alert(1)</script>";</script></html>'
        assert tester._is_search_reflection(html, "<script>alert(1)</script>") is False

    def test_not_search_plain_reflection(self, tester):
        """Payload reflected without any search context is NOT a search reflection."""
        html = '<html><body><div><script>alert(1)</script></div></body></html>'
        assert tester._is_search_reflection(html, "<script>alert(1)</script>") is False


class TestAnalyzeXSSContext:
    """Test that _analyze_xss_context correctly identifies search reflections."""

    def test_search_reflection_not_dangerous(self, tester):
        html = '<p>No results found for "<script>alert(1)</script>"</p>'
        ctx = tester._analyze_xss_context(html, "<script>alert(1)</script>")
        assert ctx['search_reflection'] is True
        assert ctx['dangerous'] is False

    def test_script_tag_is_dangerous(self, tester):
        html = '<html><script>var x = "MARKER_test";</script></html>'
        ctx = tester._analyze_xss_context(html, "MARKER_test")
        assert ctx['in_script'] is True
        assert ctx['dangerous'] is True

    def test_event_handler_is_dangerous(self, tester):
        html = '<img onerror="MARKER_test" src="x">'
        ctx = tester._analyze_xss_context(html, "MARKER_test")
        assert ctx['in_attribute'] is True
        assert ctx['dangerous'] is True

    def test_html_comment_not_dangerous(self, tester):
        html = '<!-- MARKER_test -->'
        ctx = tester._analyze_xss_context(html, "MARKER_test")
        assert ctx['in_comment'] is True
        assert ctx['dangerous'] is False

    def test_payload_not_reflected(self, tester):
        html = '<html><body>Nothing here</body></html>'
        ctx = tester._analyze_xss_context(html, "NONEXISTENT")
        assert ctx['reflected'] is False
        assert ctx['dangerous'] is False


class TestPayloadEncoding:
    """Test that encoded payloads are detected."""

    def test_html_encoded_lt_gt(self, tester):
        payload = '<script>alert(1)</script>'
        response = '&lt;script&gt;alert(1)&lt;/script&gt;'
        assert tester._is_payload_encoded(response, payload) is True

    def test_not_encoded(self, tester):
        payload = '<script>alert(1)</script>'
        response = '<script>alert(1)</script>'
        assert tester._is_payload_encoded(response, payload) is False
