import pytest
from monitor.delta_engine import _compare_vt_comments

def test_compare_vt_comments_no_new_report():
    assert _compare_vt_comments({"some": "old_data"}, None) == []
    assert _compare_vt_comments({"some": "old_data"}, {}) == []

def test_compare_vt_comments_no_vt_comments_in_new():
    old_report = {"virustotal_comments": {"data": [{"id": "1", "attributes": {"text": "old comment"}}]}}
    new_report = {"some_other_key": "data"}
    assert _compare_vt_comments(old_report, new_report) == []

def test_compare_vt_comments_no_old_report():
    new_report = {
        "virustotal_comments": {
            "data": [
                {"id": "1", "attributes": {"text": "new comment"}}
            ]
        }
    }
    deltas = _compare_vt_comments(None, new_report)
    assert len(deltas) == 1
    assert deltas[0]["field"] == "new_vt_comment"
    assert deltas[0]["value"] == "new comment"

def test_compare_vt_comments_same_comments():
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
    assert _compare_vt_comments(old_report, new_report) == []

def test_compare_vt_comments_new_comments_added():
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
    assert len(deltas) == 1
    assert deltas[0]["field"] == "new_vt_comment"
    assert deltas[0]["value"] == "comment 2"

def test_compare_vt_comments_long_comment_truncated():
    long_text = "A" * 600
    new_report = {
        "virustotal_comments": {
            "data": [
                {"id": "1", "attributes": {"text": long_text}}
            ]
        }
    }
    deltas = _compare_vt_comments(None, new_report)
    assert len(deltas) == 1
    assert deltas[0]["field"] == "new_vt_comment"
    assert deltas[0]["value"] == "A" * 500
    assert len(deltas[0]["value"]) == 500

def test_compare_vt_comments_empty_comment_text():
    new_report = {
        "virustotal_comments": {
            "data": [
                {"id": "1", "attributes": {"text": ""}},
                {"id": "2", "attributes": {}},
                {"id": "3"}
            ]
        }
    }
    assert _compare_vt_comments(None, new_report) == []

def test_compare_vt_comments_malformed_data():
    # Trigger TypeError by passing list instead of dict for attributes
    new_report_type_error = {
        "virustotal_comments": {
            "data": [
                {"id": "1", "attributes": []}
            ]
        }
    }
    assert _compare_vt_comments(None, new_report_type_error) == []

    # Trigger TypeError by having a list instead of dict for comment itself
    new_report_type_error2 = {
        "virustotal_comments": {
            "data": [
                ["not", "a", "dict"]
            ]
        }
    }
    assert _compare_vt_comments(None, new_report_type_error2) == []

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
    # Actually this would trigger TypeError in old_comment_ids = {comment.get('id') ...}
    assert _compare_vt_comments(old_report_malformed, new_report_valid) == []
