from cron.scheduler import _validate_semantic_cron_result


SEO_JOB = {"skills": ["seo-kanban-orchestrator"]}
ORDINARY_JOB = {"skills": []}


def test_ordinary_cron_keeps_legacy_success_rule():
    assert _validate_semantic_cron_result(ORDINARY_JOB, "any response") == (True, None)


def test_seo_pipeline_requires_terminal_marker():
    ok, error = _validate_semantic_cron_result(SEO_JOB, "GSC analysis finished")
    assert ok is False
    assert error is not None
    assert "PIPELINE_STATUS" in error


def test_seo_pipeline_blocks_without_executor_evidence():
    response = """PIPELINE_STATUS: completed
GSC_RUN_ID: 34
SEOAEO_RESULT: intent and scope approved
COPYWRITER_RESULT: copy delivered
"""
    ok, error = _validate_semantic_cron_result(SEO_JOB, response)
    assert ok is False
    assert error is not None
    assert "SYNC_RESULT" in error
    assert "LOCAL_VALIDATION" in error


def test_seo_pipeline_accepts_completed_with_all_evidence():
    response = """PIPELINE_STATUS: completed
GSC_RUN_ID: 34
SEOAEO_RESULT: intent and scope approved
COPYWRITER_RESULT: copy delivered
EXECUTOR_COMMIT: abc123
SYNC_RESULT: sync accepted
LOCAL_VALIDATION: build and SEO checks passed
"""
    assert _validate_semantic_cron_result(SEO_JOB, response) == (True, None)


def test_seo_pipeline_accepts_no_actionable_candidate_without_executor():
    response = """PIPELINE_STATUS: no_actionable_candidate
GSC_RUN_ID: 35
ANALYSIS_RESULT: no page/query evidence met the safe-action threshold
"""
    assert _validate_semantic_cron_result(SEO_JOB, response) == (True, None)


def test_seo_pipeline_rejects_blocked_terminal_state():
    response = """PIPELINE_STATUS: blocked
GSC_RUN_ID: 34
ANALYSIS_RESULT: seoaeo handoff blocked
ACTION_ROLLBACK: verified
"""
    ok, error = _validate_semantic_cron_result(SEO_JOB, response)
    assert ok is False
    assert error is not None
    assert "blocked" in error


def test_seo_pipeline_rejects_blocked_without_rollback_evidence():
    response = """PIPELINE_STATUS: blocked
GSC_RUN_ID: 34
ANALYSIS_RESULT: production gate failed
"""
    ok, error = _validate_semantic_cron_result(SEO_JOB, response)
    assert ok is False
    assert error is not None
    assert "ACTION_ROLLBACK" in error


def test_read_only_worker_cannot_use_mutating_execution_tools(monkeypatch):
    monkeypatch.setenv("HERMES_KANBAN_READ_ONLY", "1")

    from tools.code_execution_tool import check_sandbox_requirements
    from tools.terminal_tool import check_terminal_requirements
    from tools.file_tools import _handle_patch, _handle_write_file

    assert check_terminal_requirements() is False
    assert check_sandbox_requirements() is False
    assert "read-only" in str(_handle_write_file({"path": "x", "content": "y"}))
    assert "read-only" in str(_handle_patch({"mode": "replace"}))


def test_executor_lane_is_not_read_only(monkeypatch):
    monkeypatch.delenv("HERMES_KANBAN_READ_ONLY", raising=False)
    from tools.file_tools import _read_only_write_guard

    assert _read_only_write_guard() is None
