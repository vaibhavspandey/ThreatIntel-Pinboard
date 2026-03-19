import unittest
from monitor.delta_engine import _compare_vt_comments, _compare_urlscan

class TestDeltaEngine(unittest.TestCase):

    # --- VT Comments Tests ---

    def test_compare_vt_comments_no_new_report(self):
        self.assertEqual(_compare_vt_comments({"some": "old_data"}, None), [])
        self.assertEqual(_compare_vt_comments({"some": "old_data"}, {}), [])

    def test_compare_vt_comments_no_vt_comments_in_new(self):
        old_report = {"virustotal_comments": {"data": [{"id": "1", "attributes": {"text": "old comment"}}]}}
        new_report = {"some_other_key": "data"}
        self.assertEqual(_compare_vt_comments(old_report, new_report), [])

    def test_compare_vt_comments_no_old_report(self):
        new_report = {
            "virustotal_comments": {
                "data": [
                    {"id": "1", "attributes": {"text": "new comment"}}
                ]
            }
        }
        deltas = _compare_vt_comments(None, new_report)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["field"], "new_vt_comment")
        self.assertEqual(deltas[0]["value"], "new comment")

    def test_compare_vt_comments_same_comments(self):
        old_report = {
            "virustotal_comments": {
                "data": [
                    {"id": "1", "attributes": {"text": "comment 1"}},
                    {"id": "2", "attributes": {"text": "comment 2"}}
                ]
            }
        }
        new_report = {
            "virustotal_comments": {
                "data": [
                    {"id": "1", "attributes": {"text": "comment 1"}},
                    {"id": "2", "attributes": {"text": "comment 2"}}
                ]
            }
        }
        self.assertEqual(_compare_vt_comments(old_report, new_report), [])

    def test_compare_vt_comments_new_comments_added(self):
        old_report = {
            "virustotal_comments": {
                "data": [
                    {"id": "1", "attributes": {"text": "comment 1"}}
                ]
            }
        }
        new_report = {
            "virustotal_comments": {
                "data": [
                    {"id": "1", "attributes": {"text": "comment 1"}},
                    {"id": "2", "attributes": {"text": "comment 2"}}
                ]
            }
        }
        deltas = _compare_vt_comments(old_report, new_report)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["field"], "new_vt_comment")
        self.assertEqual(deltas[0]["value"], "comment 2")

    def test_compare_vt_comments_long_comment_truncated(self):
        long_text = "A" * 600
        new_report = {
            "virustotal_comments": {
                "data": [
                    {"id": "1", "attributes": {"text": long_text}}
                ]
            }
        }
        deltas = _compare_vt_comments(None, new_report)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["field"], "new_vt_comment")
        self.assertEqual(deltas[0]["value"], "A" * 500)
        self.assertEqual(len(deltas[0]["value"]), 500)

    def test_compare_vt_comments_empty_comment_text(self):
        new_report = {
            "virustotal_comments": {
                "data": [
                    {"id": "1", "attributes": {"text": ""}},
                    {"id": "2", "attributes": {}},
                    {"id": "3"}
                ]
            }
        }
        self.assertEqual(_compare_vt_comments(None, new_report), [])

    def test_compare_vt_comments_malformed_data(self):
        # Trigger TypeError by passing list instead of dict for attributes
        new_report_type_error = {
            "virustotal_comments": {
                "data": [
                    {"id": "1", "attributes": []}
                ]
            }
        }
        self.assertEqual(_compare_vt_comments(None, new_report_type_error), [])

        # Trigger TypeError by having a list instead of dict for comment itself
        new_report_type_error2 = {
            "virustotal_comments": {
                "data": [
                    ["not", "a", "dict"]
                ]
            }
        }
        self.assertEqual(_compare_vt_comments(None, new_report_type_error2), [])

        # Old report malformed
        old_report_malformed = {
            "virustotal_comments": {
                "data": "not a list"
            }
        }
        new_report_valid = {
            "virustotal_comments": {
                "data": [
                    {"id": "1", "attributes": {"text": "new comment"}}
                ]
            }
        }
        self.assertEqual(_compare_vt_comments(old_report_malformed, new_report_valid), [])

    # --- URLScan Tests ---

    def test_compare_urlscan_no_new_report(self):
        self.assertEqual(_compare_urlscan({"urlscan": {"results": []}}, None), [])
        self.assertEqual(_compare_urlscan({"urlscan": {"results": []}}, {}), [])
        self.assertEqual(_compare_urlscan({"urlscan": {"results": []}}, {"urlscan": {}}), [])

    def test_compare_urlscan_new_scan_detected(self):
        old_report = {"urlscan": {"results": [{"_id": "scan1"}]}}
        new_report = {"urlscan": {"results": [{"_id": "scan1"}, {"_id": "scan2"}]}}
        deltas = _compare_urlscan(old_report, new_report)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["field"], "new_urlscan_scan")
        self.assertEqual(deltas[0]["old"], 1)
        self.assertEqual(deltas[0]["new"], 2)

    def test_compare_urlscan_no_old_report_new_scan(self):
        new_report = {"urlscan": {"results": [{"_id": "scan1"}]}}
        deltas = _compare_urlscan(None, new_report)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["field"], "new_urlscan_scan")
        self.assertEqual(deltas[0]["old"], 0)
        self.assertEqual(deltas[0]["new"], 1)

    def test_compare_urlscan_domain_weaponized(self):
        old_report = {
            "urlscan": {
                "results": [
                    {"_id": "scan1", "verdicts": {"malicious": False}}
                ]
            }
        }
        new_report = {
            "urlscan": {
                "results": [
                    {"_id": "scan2", "verdicts": {"malicious": True}},
                    {"_id": "scan1", "verdicts": {"malicious": False}}
                ]
            }
        }
        deltas = _compare_urlscan(old_report, new_report)
        # Should detect new scan AND weaponization
        self.assertEqual(len(deltas), 2)

        # Check new scan delta
        new_scan_delta = next(d for d in deltas if d["field"] == "new_urlscan_scan")
        self.assertEqual(new_scan_delta["old"], 1)
        self.assertEqual(new_scan_delta["new"], 2)

        # Check weaponization delta
        weaponized_delta = next(d for d in deltas if d["field"] == "DOMAIN_WEAPONIZED")
        self.assertEqual(weaponized_delta["message"], "URLScan verdict changed to malicious")
        self.assertEqual(weaponized_delta["scan_id"], "scan2")

    def test_compare_urlscan_not_weaponized_if_already_malicious(self):
        old_report = {
            "urlscan": {
                "results": [
                    {"_id": "scan1", "verdicts": {"malicious": True}}
                ]
            }
        }
        new_report = {
            "urlscan": {
                "results": [
                    {"_id": "scan2", "verdicts": {"malicious": True}},
                    {"_id": "scan1", "verdicts": {"malicious": True}}
                ]
            }
        }
        deltas = _compare_urlscan(old_report, new_report)
        # Should only detect new scan
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["field"], "new_urlscan_scan")

    def test_compare_urlscan_malformed_data(self):
        # results is not a list - this should still return a delta because len("not a list") is 10 > 0
        new_report_malformed = {"urlscan": {"results": "not a list"}}
        deltas = _compare_urlscan(None, new_report_malformed)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["field"], "new_urlscan_scan")

        # results contains non-dict items
        new_report_malformed2 = {"urlscan": {"results": [None]}}
        deltas = _compare_urlscan(None, new_report_malformed2)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["field"], "new_urlscan_scan")

        # Missing verdicts key
        old_report = {"urlscan": {"results": [{"_id": "scan1"}]}}
        new_report = {"urlscan": {"results": [{"_id": "scan1"}]}}
        self.assertEqual(_compare_urlscan(old_report, new_report), [])

if __name__ == "__main__":
    unittest.main()
