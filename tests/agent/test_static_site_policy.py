import tempfile
import unittest
from pathlib import Path

from agent.codex_runtime import _codex_static_site_completion_error, _record_codex_project_roots
from agent.turn_finalizer import _static_site_completion_error
from tools.static_site_policy import (
    _acquisition_method_is_valid,
    _post_materialization_copy_is_safe,
    _resolve_publishing_routes,
    guard_execute_code,
    reset_static_site_turn,
    validate_receipt_write,
    guard_path,
    prepare_receipt_content,
    guard_terminal_command,
    validate_materialization,
    validate_template_design,
)


class StaticSitePolicyTests(unittest.TestCase):
    def setUp(self):
        reset_static_site_turn(self.id())

    def test_authorized_existing_seo_project_allows_terminal_git_status(self):
        project = "/home/shen/dev/0calfood/0calfood"
        reset_static_site_turn("existing-seo-terminal-test")
        try:
            self.assertIsNone(
                guard_terminal_command(
                    "git status --short --branch",
                    workdir=project,
                    session_cwd=project,
                )
            )
        finally:
            reset_static_site_turn("existing-seo-terminal-test-cleanup")

    def test_unknown_existing_project_terminal_remains_fail_closed(self):
        project = "/home/shen/dev/unknown-existing-site"
        reset_static_site_turn("unknown-existing-terminal-test")
        try:
            self.assertTrue(
                guard_terminal_command(
                    "git status --short --branch",
                    workdir=project,
                    session_cwd=project,
                )
            )
        finally:
            reset_static_site_turn("unknown-existing-terminal-test-cleanup")

    def test_pre_materialization_terminal_reads_are_blocked(self):
        project = "/home/shen/dev/static-site-policy-regression"

        self.assertTrue(guard_terminal_command("rg --files /home/shen/dev", session_cwd=project))
        self.assertTrue(guard_terminal_command(f"sed -n '1,5p' {project}/index.html", session_cwd=project))
        self.assertTrue(guard_terminal_command(f"stat -c %F {project}/index.html", session_cwd=project))
        self.assertTrue(guard_terminal_command("rg --files", session_cwd="/home/shen/dev"))

    def test_pre_materialization_rejects_copying_the_local_archive(self):
        project = "/home/shen/dev/static-site-policy-copy-regression"
        source_cwd = "/home/shen/.hermes/skills/research/web-editorial-layout-references/templates/sites/14-wirecutter"
        self.assertTrue(
            guard_terminal_command(
                f"cp -a . {project}/",
                workdir=source_cwd,
                session_cwd=source_cwd,
            )
        )

    def test_free_template_acquisition_method_accepts_official_descriptions(self):
        for value in (
            "official GitHub repository",
            "official GitHub repository clone",
            "official-github-download",
            "official source: Git repository",
            "local-approved-source",
        ):
            self.assertTrue(_acquisition_method_is_valid(value), value)
        for value in ("github", "random-download", "unverified-source"):
            self.assertFalse(_acquisition_method_is_valid(value), value)

    def test_receipt_normalizes_nested_download_root_and_rebuilds_file_manifest(self):
        with tempfile.TemporaryDirectory(dir="/tmp/hermes-free-templates") as raw:
            wrapper = Path(raw)
            source = wrapper / "src" / "ZenBlog"
            source.mkdir(parents=True)
            (source / "index.html").write_text("<html></html>")
            (source / "category.html").write_text("<html></html>")
            (source / "assets.css").write_text("body {}")
            (source / "assets.js").write_text("// shell")
            data = {
                "execution_mode": "free-template-review",
                "source_template_directory": str(wrapper),
                "template_files": ["index.html", "landing.html"],
            }
            prepared = prepare_receipt_content(
                "/home/shen/dev/nested-root-regression/docs/template-materialization.json",
                __import__("json").dumps(data),
            )
            result = __import__("json").loads(prepared)
            self.assertEqual(str(source), result["source_template_directory"])
            self.assertEqual(
                ["assets.css", "assets.js", "category.html", "index.html"],
                result["template_files"],
            )
            blocked = guard_terminal_command(
                f"cp -a {wrapper}/. /home/shen/dev/nested-root-regression/",
                workdir="/home/shen/dev",
                session_cwd="/home/shen/dev",
            )
            self.assertIn("nested template root", blocked)

    def test_execute_code_cannot_invoke_nested_terminal_for_project_mutation(self):
        error = guard_execute_code(
            "from hermes_tools import terminal; terminal('cp -a /tmp/hermes-free-templates/x /home/shen/dev/site')",
            session_cwd="/home/shen/dev/site",
        )
        self.assertIn("nested terminal", error)

    def test_copy_preflights_staged_route_contract_before_destination_mutation(self):
        with tempfile.TemporaryDirectory(dir="/tmp/hermes-free-templates") as raw:
            staged = Path(raw)
            (staged / "index.html").write_text("<html></html>")
            (staged / "category.html").write_text("<html></html>")
            (staged / "single-post.html").write_text("<html></html>")
            (staged / "styles.css").write_text("body {}")
            (staged / "app.js").write_text("// shell")
            error = guard_terminal_command(
                f"cp -a {staged}/. /home/shen/dev/route-preflight-regression/",
                workdir="/home/shen/dev",
                session_cwd="/home/shen/dev",
            )
            self.assertIsNone(error)

    def test_rejected_receipt_locks_project_operations_for_the_turn(self):
        root = Path("/home/shen/dev/receipt-lock-regression")
        reset_static_site_turn("receipt-lock-test")
        try:
            receipt = {
                "status": "materialized",
                "execution_mode": "free-template-review",
                "deployment_mode": "copy-only",
                "selected_template_name": "test",
                "source_url": "https://bootstrapmade.com/test-template/",
                "source_catalog": "bootstrapmade-free-catalog",
                "source_catalog_template_count": 179,
                "license": "MIT",
                "license_url": "https://example.test/license",
                "acquisition_method": "official-bootstrapmade-download",
                "destination_template_directory": str(root),
                "template_files": [],
            }
            error = validate_receipt_write(
                root / "docs/template-materialization.json",
                __import__("json").dumps(receipt),
            )
            self.assertIn("Only the same receipt", error)
            locked = guard_terminal_command(
                "cp -a /tmp/hermes-free-templates/editorial/. /home/shen/dev/receipt-lock-regression/",
                workdir="/home/shen/dev",
                session_cwd="/home/shen/dev",
            )
            self.assertIn("turn already failed", locked)
        finally:
            reset_static_site_turn("receipt-lock-test-cleanup")

    def test_pre_materialization_allows_copying_staged_free_template(self):
        project = "/home/shen/dev/free-template-policy-regression"
        staged = "/tmp/hermes-free-templates/editorial/unpacked"
        self.assertIsNone(
            guard_terminal_command(
                f"cp -a {staged} {project}/",
                workdir="/home/shen/dev",
                session_cwd="/home/shen/dev",
            )
        )

    def test_free_template_routes_allow_pages_directory_equivalents(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            routes = ["index.html", "pages/category.html", "pages/article.html", "pages/search.html"]
            for route in routes:
                path = root / route
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("<html></html>")
            selected, error = _resolve_publishing_routes(root, routes)
            self.assertIsNone(error)
            self.assertEqual(
                ["index.html", "pages/category.html", "pages/article.html", "pages/search.html"],
                [path.relative_to(root).as_posix() for path in selected],
            )

    def test_free_template_build_and_dependency_commands_are_blocked_in_staging(self):
        for command in ("npm ci", "npm run build", "pnpm install", "yarn add vite"):
            error = guard_terminal_command(
                command,
                workdir="/tmp/hermes-free-templates/editorial",
                session_cwd="/tmp/hermes-free-templates/editorial",
            )
            self.assertIn("forbids", error)

    def test_arbitrary_tmp_static_writes_and_preview_commands_are_blocked(self):
        self.assertIn("arbitrary /tmp", guard_path("/tmp/furniture-fieldnotes/index.html", "write"))
        self.assertIn(
            "arbitrary /tmp",
            guard_terminal_command(
                "rm -rf /tmp/furniture-fieldnotes && mkdir -p /tmp/furniture-fieldnotes/assets",
                workdir="/tmp",
                session_cwd="/tmp",
            ),
        )
        self.assertIn(
            "arbitrary /tmp",
            guard_terminal_command(
                "python3 -m http.server 8765 --bind 127.0.0.1",
                workdir="/tmp/furniture-fieldnotes",
                session_cwd="/tmp/furniture-fieldnotes",
            ),
        )
        self.assertIn(
            "arbitrary /tmp",
            guard_execute_code("from hermes_tools import write_file; write_file('/tmp/furniture-fieldnotes/index.html', '<html></html>')"),
        )

    def test_package_only_receipts_are_retired_not_a_fallback_mode(self):
        with tempfile.TemporaryDirectory() as raw:
            valid, reason = validate_materialization(
                raw,
                {"status": "materialized", "execution_mode": "package-only"},
                require_utilities=False,
            )
            self.assertFalse(valid)
            self.assertIn("retired", reason)
            self.assertIn("archive-only", reason)

    def test_free_template_receipt_requires_source_staging_and_route_equivalents(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for path in ("index.html", "styles.css", "app.js"):
                (root / path).write_text("x")
            from tools.static_site_policy import validate_materialization
            manifest = {
                "status": "materialized",
                "execution_mode": "free-template-review",
                "deployment_mode": "copy-only",
                "selected_template_name": "test",
                "source_url": "https://bootstrapmade.com/test-template/",
                "source_catalog": "bootstrapmade-free-catalog",
                "source_catalog_template_count": 179,
                "license": "MIT",
                "license_url": "https://example.test/license",
                "acquisition_method": "official GitHub repository clone",
                "destination_template_directory": str(root),
                "template_files": ["index.html", "styles.css", "app.js"],
                "source_snapshot_sha256": {
                    "index.html": "0" * 64,
                    "styles.css": "0" * 64,
                    "app.js": "0" * 64,
                },
                "asset_roots": ["."],
                "attempted_candidates": ["https://bootstrapmade.com/test-template/"],
                "materialized_at_utc": "2026-08-07T00:00:00Z",
            }
            valid, reason = validate_materialization(root, manifest, require_utilities=False)
            self.assertFalse(valid)
            self.assertIn("route_adaptations must list", reason)

    def test_pre_materialization_allows_only_project_root_metadata(self):
        project = "/home/shen/dev/static-site-policy-regression"
        self.assertIsNone(guard_terminal_command(f"stat -c %F {project}", session_cwd=project))

    def test_stale_receipt_is_not_a_pre_materialization_read_boundary_bypass(self):
        self.assertTrue(guard_path("/home/shen/dev/static-site-policy-regression/docs/template-materialization.json", "read"))

    def test_authenticated_project_rejects_recursive_shell_copy(self):
        project = "/home/shen/dev/furniture-notes"
        self.assertFalse(
            _post_materialization_copy_is_safe(
                "cp -a . /home/shen/dev/furniture-notes/",
                "/home/shen/.hermes/skills/research/web-editorial-layout-references/templates/sites/14-wirecutter",
                Path(project),
            )
        )
        self.assertTrue(
            _post_materialization_copy_is_safe(
                "cp assets/dining-chair.png assets/hero.jpg",
                project,
                Path(project),
            )
        )

    def test_codex_projected_tool_paths_feed_the_completion_gate(self):
        class Agent:
            _turn_file_mutation_paths = set()

        _record_codex_project_roots(
            Agent(),
            [{
                "role": "assistant",
                "tool_calls": [{
                    "function": {
                        "name": "exec_command",
                        "arguments": '{"command":"cp -a . /home/shen/dev/furniture-notes/","cwd":"/tmp"}',
                    }
                }],
            }],
        )
        self.assertEqual({"/home/shen/dev/furniture-notes"}, Agent._turn_file_mutation_paths)

    def test_codex_gate_delegates_to_shared_completion_gate(self):
        class Agent:
            _turn_file_mutation_paths = set()
            _turn_failed_file_mutations = {}
            cwd = None
            workdir = None
            terminal_cwd = None

        reason = _codex_static_site_completion_error(Agent())
        self.assertIsNone(reason)

    def test_authorized_existing_seo_project_skips_new_site_materialization_gate(self):
        class Agent:
            _turn_failed_file_mutations = {}
            _turn_file_mutation_paths = {
                "/home/shen/dev/0calfood/0calfood/articles/example.html"
            }
            cwd = None
            workdir = None
            terminal_cwd = None

        reason = _static_site_completion_error(Agent())
        self.assertIsNone(reason)

    def test_finalizer_blocks_success_after_a_rejected_project_mutation(self):
        class RejectedAgent:  # only the finalizer state needed for this hard-failure path
            _turn_failed_file_mutations = {
                "/home/shen/dev/static-site-policy-regression/index.html": {
                    "error_preview": "rejected file mutation"
                }
            }
            _turn_file_mutation_paths = set()
            cwd = None
            workdir = None
            terminal_cwd = None

        reason = _static_site_completion_error(RejectedAgent())
        self.assertIn("rejected file mutation", reason)

    def test_all_numbered_packages_pass_design_and_route_contract_gate(self):
        failures = [
            (number, validate_template_design(number)[1])
            for number in range(1, 31)
            if not validate_template_design(number)[0]
        ]
        self.assertEqual([], failures)


if __name__ == "__main__":
    unittest.main()
