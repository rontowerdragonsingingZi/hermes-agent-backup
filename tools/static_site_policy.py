"""Hard policy gates for free-template static-site publishing.

The static-site skills are prompt guidance, but the dangerous transitions are
tool operations.  This module keeps those transitions fail-closed:

* existing projects under ``/home/shen/dev`` may be checked for existence, but
  their content is unreadable until a valid materialization receipt exists;
* the default receipt records an official free-template source and license;
* legacy numbered-package receipts are rejected and retained only for a clear migration error;
* generators and renderer files are forbidden for both workflows.

The policy deliberately does not inspect or mutate project content while
deciding whether a normal read is allowed.  Receipt validation is the one
exception: it must inspect the newly copied package to authenticate the
materialization operation itself.
"""

from __future__ import annotations

import hashlib
from html import unescape
import http.client
import json
import re
import shlex
import stat
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from contextvars import ContextVar
from pathlib import Path
from typing import Any


DEV_ROOT = Path("/home/shen/dev")
# Existing production sites authorized for evidence-backed SEO maintenance.
# These are not new-site materialization targets and therefore do not require
# docs/template-materialization.json. Unknown /home/shen/dev projects remain
# fail-closed behind the normal materialization policy.
EXISTING_SEO_PROJECT_ROOT_NAMES = {
    "0calfood",      # sobalife.tw active source root
    "sobalife",      # sobalife.tw legacy alias, if present
}
HOME_ROOT = Path("/home/shen")
HOME_ALLOWED_TOP_LEVEL = {
    "dev", ".hermes", ".codex", ".cache", ".config", ".local", ".npm",
    ".ssh", "Downloads", "Desktop", "Documents", "Pictures", "Videos", "Music",
}
SITES_ROOT = (
    Path(__file__).resolve().parents[2]
    / "skills/research/web-editorial-layout-references/templates/sites"
)
RECEIPT_NAME = "template-materialization.json"
REVIEW_NAME = "template-review.json"
FREE_EXECUTION_MODE = "free-template-review"
LEGACY_EXECUTION_MODE = "package-only"
FREE_TEMPLATE_STAGING_ROOTS = (
    Path("/tmp/hermes-free-templates"),
    Path(__file__).resolve().parents[2] / "skills/research/web-editorial-layout-references/templates/free-sources",
)
LOCAL_TEMPLATE_BUNDLE_ROOT = Path(__file__).resolve().parents[2] / "BootstrapMade-Free-Info-Templates"
FIXED_TEMPLATE_CATALOG_ID = "bootstrapmade-free-catalog"
FIXED_TEMPLATE_CATALOG_URL = "https://bootstrapmade.com/"
FIXED_TEMPLATE_CATALOG_HOST = "bootstrapmade.com"
FIXED_TEMPLATE_MIN_COUNT = 50
REQUIRED_FILES = (
    "index.html",
    "category.html",
    "article.html",
    "search.html",
    "styles.css",
    "app.js",
    "content.json",
    "template.json",
    "source-trace.json",
)
SHELL_FILES = tuple(name for name in REQUIRED_FILES if name != "content.json")
PUBLIC_UTILITY_FILES = ("robots.txt", "sitemap.xml", "favicon.svg", "404.html")
PUBLISHING_HTML_FILES = ("index.html", "category.html", "article.html", "search.html")
PUBLISHING_ROUTE_ALIASES = {
    "index.html": {"index.html", "home.html"},
    "category.html": {"category.html", "blog.html", "news.html", "archive.html"},
    "article.html": {"article.html", "article-detail.html", "blog-details.html", "single.html", "single-post.html", "post.html"},
    "search.html": {"search.html", "search-results.html", "results.html"},
}
CONTENT_IDENTITY_KEYS = ("siteTitle", "brand", "heroTitle", "articleTitle")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PROJECT_PATH_RE = re.compile(r"^/home/shen/dev/([^/]+)(?:/|$)")
_FORBIDDEN_GENERATOR_RE = re.compile(
    r"(?:^|[\s/])(?:build_site\.py|template_renderer\.py|component_generator\.py|site_generator\.py|render_site\.py|generate_site\.py|populate_[A-Za-z0-9_-]+\.py|[A-Za-z0-9_-]+_materialize\.py|docs/[A-Za-z0-9_-]+\.py)(?:$|[\s'\";|&])"
)
_CONTENT_READ_RE = re.compile(
    r"(?:^|[\s;&|()])(?:cat|head|tail|less|more|sed|awk|grep|rg|git\s+(?:show|diff)|"
    r"python(?:3)?\s+-c|node\s+-e|find)(?:[\s;&|()])"
)
_PLACEHOLDER_RE = re.compile(
    r"(?:editorial template|project brand|replace (?:this|with)|"
    r"(?:summary|content) placeholder|story title|topic index|article detail|"
    r"secondary story|another indexed|neutral content|answer-first summary|"
    r"get started|authentication|surface tablet|example article|"
    r"was this article helpful|one article you can continue|"
    r"lorem ipsum|magz|magazine template|html5\\s+template|css3\\s+template|fusce|donec|maecenas|"
    r"phasellus|proin|nulla facilisis|by subscribing|your mail|"
    r"copyright[^\n]{0,40}magz|category:\s*computer|troubleshoot|"
    r"programming|\bsingle\b)",
    re.I,
)
_TEMPLATE_VISIBLE_RE = re.compile(
    r"\b(?:home|about(?: us)?|blog details|author profile|search results|read more|"
    r"category section|featured posts|starter section|contact|search|"
    r"politics|sports|entertainment|career|cloud|programming|health|education|gaming|"
    r"michael chen|sarah anderson|senior web developer|web development|"
    r"a108 adam street|new york, ny|info@example\.com|"
    r"dolorum optio tempore|nisi magni odit|poss(?:imus) soluta|"
    r"modern development environments|edge computing|progressive web apps|"
    r"the future of web development|neque porro quisquam|sed ut perspiciatis)\b",
    re.I,
)
_TEMPLATE_IMAGE_RE = re.compile(
    r"(?:^|/)(?:blog-post(?:-[^/]+)?|blog-hero-[^/]+|person-[fm]-\d+|"
    r"about-wide-[^/]+|cta-[^/]+|misc-[^/]+)\.(?:webp|png|jpe?g)$",
    re.I,
)


def _visible_html_text(source: str) -> str:
    source = re.sub(r"<!--.*?-->", " ", source or "", flags=re.S)
    source = re.sub(r"<(?:script|style|noscript)\b.*?</(?:script|style|noscript)>", " ", source, flags=re.I | re.S)
    source = re.sub(r"<[^>]+>", " ", source)
    return re.sub(r"\s+", " ", unescape(source)).strip()


_WRITE_RE = re.compile(
    r"(?:>|>>|printf\b|tee\b|sed\s+-i|perl\s+-[0-9]*pi|python(?:3)?\s+-|node\s+-e|"
    r"npm\s+(?:run|exec)|yarn\s+(?:run|exec))"
)

# Static-site policy is evaluated inside tool calls, while the agent turn
# state lives one layer above the tools. Keep fail-fast state in a ContextVar
# so concurrent tool workers inherit the same turn boundary.
_STATIC_SITE_TURN_STATE: ContextVar[dict[str, Any] | None] = ContextVar(
    "static_site_turn_state", default=None
)


def reset_static_site_turn(turn_id: str) -> None:
    """Start a clean static-site policy scope for one agent turn."""
    _STATIC_SITE_TURN_STATE.set({
        "turn_id": turn_id,
        "selected_root": None,
        "blocked_root": None,
        "blocked_reason": None,
    })


def _static_site_turn_state() -> dict[str, Any] | None:
    return _STATIC_SITE_TURN_STATE.get()


def _static_site_turn_guard(root: Path | None) -> str | None:
    state = _static_site_turn_state()
    if state is None or root is None:
        return None
    blocked_root = state.get("blocked_root")
    if blocked_root is not None:
        return (
            "BLOCKED: static-site turn already failed for "
            f"{blocked_root}. Stop this turn; do not switch project roots, "
            "templates, staging directories, or generators."
        )
    selected_root = state.get("selected_root")
    if selected_root is None:
        state["selected_root"] = root
        return None
    if root != selected_root:
        return (
            "BLOCKED: one static-site turn may use only one project root. "
            f"The selected root is {selected_root}; do not continue with {root}."
        )
    return None


def _fail_static_site_turn(root: Path, reason: str) -> None:
    state = _static_site_turn_state()
    if state is not None and state.get("blocked_root") is None:
        state["blocked_root"] = root
        state["blocked_reason"] = reason


def _clear_static_site_turn_recovery(root: Path) -> None:
    state = _static_site_turn_state()
    if state is not None and state.get("blocked_root") == root:
        state["blocked_root"] = None
        state["blocked_reason"] = None


def _resolved(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _in_dev_scope(path: str | Path) -> bool:
    candidate = _resolved(path)
    try:
        candidate.relative_to(DEV_ROOT)
        return True
    except ValueError:
        return False


def _is_free_staging_path(path: str | Path) -> bool:
    candidate = _resolved(path)
    return any(
        staging == candidate or staging in candidate.parents
        for staging in FREE_TEMPLATE_STAGING_ROOTS
    )


def _is_local_template_bundle_path(path: str | Path) -> bool:
    candidate = _resolved(path)
    return candidate == LOCAL_TEMPLATE_BUNDLE_ROOT or LOCAL_TEMPLATE_BUNDLE_ROOT in candidate.parents


def _unapproved_tmp_static_path(path: str | Path) -> bool:
    candidate = _resolved(path)
    try:
        candidate.relative_to(Path('/tmp'))
    except ValueError:
        return False
    if _is_free_staging_path(candidate):
        return False
    return candidate.suffix.lower() in {'.html', '.htm', '.css', '.js', '.json', '.svg', '.xml'}


def _unapproved_tmp_static_operation(value: str) -> bool:
    raw = value or ''
    references = re.findall(r"/tmp/[^\s'\";&|()<>]+", raw)
    if not references:
        return False
    if any(_unapproved_tmp_static_path(reference) for reference in references):
        return True
    return bool(
        re.search(r"(?:python(?:3)?\s+-|write_file|write_text|write_bytes|mkdir|rmtree|rm\s+-r|http\.server|\bzip(?:\s|$))", raw, re.I)
        and any(not _is_free_staging_path(reference) for reference in references)
    )


def _discover_staged_template_root(path: str | Path) -> Path:
    candidate = _resolved(path)
    if not candidate.is_dir():
        return candidate

    def usable(root: Path) -> bool:
        return (
            (root / "index.html").is_file()
            and any(
                item.suffix.lower() == ".css"
                for item in root.rglob("*.css")
                if "node_modules" not in item.parts
            )
            and any(
                item.suffix.lower() == ".js"
                for item in root.rglob("*.js")
                if "node_modules" not in item.parts
            )
        )

    nested = []
    for index in candidate.rglob("index.html"):
        root = index.parent
        if root == candidate or "node_modules" in root.parts or "docs" in root.parts:
            continue
        if usable(root):
            nested.append(root)
    unique = sorted(set(nested), key=lambda item: (len(item.parts), item.as_posix()))
    if len(unique) == 1:
        nested_root = unique[0]
        if not usable(candidate):
            return nested_root
        candidate_assets = [
            item
            for item in candidate.rglob("*")
            if item.is_file()
            and item.suffix.lower() in {".css", ".js"}
            and "node_modules" not in item.parts
            and nested_root not in item.parents
        ]
        candidate_has_shell_assets = {
            item.suffix.lower() for item in candidate_assets
        } >= {".css", ".js"}
        if not candidate_has_shell_assets:
            return nested_root
    return candidate
def _staged_template_files(root: Path) -> list[str]:
    """List the original HTML/CSS/JS shell relative to its real staging root."""
    if not root.is_dir():
        return []
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".html", ".css", ".js"}
        and "node_modules" not in path.parts
        and "docs" not in path.parts
    )


def unmanaged_home_project_for(path: str | Path) -> Path | None:
    """Return a direct home-level project that must not host a static site."""
    candidate = _resolved(path)
    try:
        relative = candidate.relative_to(HOME_ROOT)
    except ValueError:
        return None
    if not relative.parts:
        return None
    top = relative.parts[0]
    if top in HOME_ALLOWED_TOP_LEVEL or top.startswith('.'):
        return None
    return HOME_ROOT / top


def project_root_for(path: str | Path) -> Path | None:
    """Return the direct ``/home/shen/dev/<project>`` parent, if any."""
    candidate = _resolved(path)
    try:
        relative = candidate.relative_to(DEV_ROOT)
    except ValueError:
        return None
    if not relative.parts:
        return None
    return DEV_ROOT / relative.parts[0]


def is_authorized_existing_seo_project(root: Path | None) -> bool:
    """Allow only registered existing sites to bypass new-site materialization."""
    return bool(
        root is not None
        and root.name in EXISTING_SEO_PROJECT_ROOT_NAMES
        and root.is_dir()
    )


def template_source_for(path: str | Path) -> Path | None:
    """Return the numbered template root when path is inside the local library."""
    candidate = _resolved(path)
    try:
        relative = candidate.relative_to(SITES_ROOT)
    except ValueError:
        return None
    if not relative.parts:
        return SITES_ROOT
    return SITES_ROOT / relative.parts[0]


def _receipt_path(project_root: Path) -> Path:
    return project_root / "docs" / RECEIPT_NAME


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _html_shell_signature_text(text: str) -> str:
    """Hash HTML structure while ignoring permitted editorial value changes."""
    text = re.sub(r">[^<]*<", "><", text)
    text = re.sub(r"(<[^>]*class=[\x22\x27][^\x22\x27]*media-placeholder[^\x22\x27]*[\x22\x27][^>]*?)\s+style=[\x22][^\x22]*[\x22]", r"\1", text)
    text = re.sub(r"<meta\b[^>]*(?:name=[\x22\x27](?:description|robots)[\x22\x27]|property=[\x22\x27]og:[^\x22\x27]+[\x22\x27])[^>]*>", "", text, flags=re.I)
    text = re.sub(r"<link\b[^>]*(?:rel=[\x22\x27](?:canonical|icon)[\x22\x27])[^>]*>", "", text, flags=re.I)
    text = re.sub(r"(\s+(?:src|srcset|alt|aria-label|content|placeholder)=)[\"\'][^\"\']*[\"\']", r"\1\"<mutable>\"", text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _html_shell_signature(path: Path) -> str:
    return _html_shell_signature_text(path.read_text(encoding="utf-8", errors="ignore"))


def _js_shell_signature_text(text: str) -> str:
    """Hash JavaScript structure while ignoring permitted editorial strings."""
    text = re.sub(r"\"(?:\\.|[^\"\\])*\"", "\"<mutable>\"", text)
    text = re.sub(r"\x27(?:\\.|[^\x27\\])*\x27", "\x27<mutable>\x27", text)
    text = re.sub(r"`(?:\\.|[^`\\])*`", "`<mutable>`", text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _js_shell_signature(path: Path) -> str:
    return _js_shell_signature_text(path.read_text(encoding="utf-8", errors="ignore"))


def _copy_matches_source(name: str, source: Path, destination: Path) -> bool:
    if not destination.is_file():
        return False
    if name.endswith(".html"):
        return _html_shell_signature(source) == _html_shell_signature(destination)
    if name == "app.js":
        return _js_shell_signature(source) == _js_shell_signature(destination)
    if name == "content.json":
        try:
            json.loads(destination.read_text(encoding="utf-8"))
            return True
        except (OSError, UnicodeError, json.JSONDecodeError):
            return False
    return _sha256(source) == _sha256(destination)


def _same_path(left: str | Path, right: Path) -> bool:
    try:
        return _resolved(left) == right
    except (OSError, ValueError):
        return False


def _package_for_number(number: Any) -> Path | None:
    try:
        number = int(number)
    except (TypeError, ValueError):
        return None
    if not 1 <= number <= 30:
        return None
    matches = sorted(SITES_ROOT.glob(f"{number:02d}-*"))
    return matches[0] if len(matches) == 1 and matches[0].is_dir() else None


def _hash_map_is_valid(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and all(isinstance(value.get(name), str) and _SHA256_RE.fullmatch(value[name]) for name in SHELL_FILES)
    )


def _missing_local_references(root: Path, text_files: list[Path]) -> list[str]:
    missing = []
    attr_re = re.compile(r"(?:href|src)=[\"\']([^\"\']+)", re.I)
    css_re = re.compile(r"url\(\s*[\"\']?([^\"\')]+)", re.I)
    for source in text_files:
        text = source.read_text(encoding='utf-8', errors='ignore')
        references = attr_re.findall(text) if source.suffix.lower() == '.html' else css_re.findall(text)
        for raw in references:
            value = raw.strip()
            if not value or value.startswith(('#', '/', 'http://', 'https://', 'data:', 'mailto:', 'tel:', 'javascript:')):
                continue
            value = value.split('#', 1)[0].split('?', 1)[0]
            if not value:
                continue
            candidate = (source.parent / value).resolve(strict=False)
            try:
                candidate.relative_to(root)
            except ValueError:
                missing.append(f'{source.relative_to(root)} -> {value}')
                continue
            if not candidate.is_file() and not (candidate.is_dir() and (candidate / 'index.html').is_file()):
                missing.append(f'{source.relative_to(root)} -> {value}')
    return sorted(set(missing))


def _route_adaptation_plan(
    root: Path, html_routes: list[str], manifest: dict[str, Any] | None = None
) -> tuple[list[dict[str, str]], str | None]:
    """Return a controlled plan for HTML routes absent from the source shell.

    Missing route pages may be completed after receipt authentication by
    adapting an existing source page. This never permits a generated shell:
    every adaptation must name an existing copied HTML source file and a
    literal project-root target route.
    """
    normalized = [Path(raw).as_posix() for raw in html_routes if isinstance(raw, str)]
    missing = []
    for required in PUBLISHING_HTML_FILES:
        aliases = PUBLISHING_ROUTE_ALIASES.get(required, {required})
        if not any(Path(path).name in aliases for path in normalized):
            missing.append(required)
    if not missing:
        return [], None
    if manifest is None:
        return [], None
    raw_entries = manifest.get("route_adaptations")
    if not isinstance(raw_entries, list):
        return [], "route_adaptations must list missing route completions"
    by_target: dict[str, dict[str, str]] = {}
    for entry in raw_entries:
        if not isinstance(entry, dict):
            return [], "route_adaptations contains an invalid entry"
        target = str(entry.get("target_file") or entry.get("target_route") or "").strip()
        source = str(entry.get("source_file") or entry.get("source_route") or "").strip()
        method = str(entry.get("method") or "").strip()
        if target not in PUBLISHING_HTML_FILES:
            return [], f"route_adaptations has an invalid target: {target}"
        source_path = Path(source)
        if source_path.is_absolute() or ".." in source_path.parts or source_path.suffix.lower() != ".html":
            return [], f"route_adaptations has an invalid source: {source}"
        if source_path.as_posix() not in normalized or not (root / source_path).is_file():
            return [], f"route_adaptations source is not a copied HTML file: {source}"
        if method not in {"copy-and-adapt", "adapt-existing-page"}:
            return [], f"route_adaptations method is invalid for {target}"
        by_target[target] = {
            "target_file": target,
            "source_file": source_path.as_posix(),
            "method": method,
        }
    missing_entries = [required for required in missing if required not in by_target]
    if missing_entries:
        return [], "route_adaptations must cover: " + ", ".join(missing_entries)
    return [by_target[required] for required in missing], None


def _automatic_route_adaptations(root: Path, html_routes: list[str]) -> list[dict[str, str]]:
    """Build the receipt plan from the actual staged/copied HTML tree."""
    normalized = [Path(raw).as_posix() for raw in html_routes if isinstance(raw, str)]
    adaptations = []
    for required in PUBLISHING_HTML_FILES:
        aliases = PUBLISHING_ROUTE_ALIASES.get(required, {required})
        if any(Path(path).name in aliases for path in normalized):
            continue
        preferred = (
            ["single-post.html", "blog-details.html", "article.html", "post.html", "index.html"]
            if required == "article.html"
            else ["category.html", "blog.html", "news.html", "index.html"]
        )
        source = next(
            (path for name in preferred for path in normalized if Path(path).name == name),
            normalized[0] if normalized else "",
        )
        if source:
            adaptations.append({
                "target_file": required,
                "source_file": source,
                "method": "copy-and-adapt",
                "status": "planned",
            })
    return adaptations


def _resolve_publishing_routes(
    root: Path, html_routes: list[str] | None
) -> tuple[list[Path], str | None]:
    """Resolve the four required route classes for a copied free template."""
    candidates = PUBLISHING_HTML_FILES if html_routes is None else html_routes
    if not isinstance(candidates, (list, tuple)) or not candidates:
        return [], "template declares no publishing HTML routes"
    normalized: list[str] = []
    for raw in candidates:
        if not isinstance(raw, str) or not raw.strip():
            return [], "template declares an invalid HTML route"
        path = Path(raw)
        if path.is_absolute() or ".." in path.parts or path.suffix.lower() != ".html":
            return [], f"template declares an invalid HTML route: {raw}"
        if not (root / path).is_file():
            return [], f"declared publishing route is missing: {path.as_posix()}"
        normalized.append(path.as_posix())

    selected: list[str] = []
    for required in PUBLISHING_HTML_FILES:
        aliases = PUBLISHING_ROUTE_ALIASES.get(required, {required})
        matches = [path for path in normalized if Path(path).name in aliases]
        if not matches:
            return [], f"template is missing an equivalent {required} route"
        selected.append(matches[0])
    return [root / path for path in selected], None


def validate_publishing_artifact(
    project_root: str | Path, *, asset_roots: list[str] | None = None,
    html_routes: list[str] | None = None,
) -> tuple[bool, str]:
    """Validate content, SEO assets, served permissions, and placeholder removal."""
    root = _resolved(project_root)
    declared_asset_roots = asset_roots or ["assets"]
    for raw_asset_root in declared_asset_roots:
        asset_root = root / raw_asset_root
        if not asset_root.is_dir():
            return False, f"project is missing the declared served asset directory: {raw_asset_root}"
    route_files, route_error = _resolve_publishing_routes(root, html_routes)
    if route_error:
        return False, route_error
    html_files = sorted(
        path for path in root.rglob("*.html")
        if "docs" not in path.parts and "node_modules" not in path.parts
    )
    css_files = sorted(
        path for path in root.rglob("*.css")
        if "docs" not in path.parts and "node_modules" not in path.parts
    )
    js_files = sorted(
        path for path in root.rglob("*.js")
        if "docs" not in path.parts and "node_modules" not in path.parts
    )
    served_files = html_files + [root / name for name in PUBLIC_UTILITY_FILES]
    served_files.extend(path for path in root.rglob("*") if path.is_file() and "docs" not in path.parts)

    for path in served_files:
        if not path.is_file():
            return False, f"served artifact is missing {path.relative_to(root)}; create the project-root favicon.svg and reference it from every HTML route"
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o444 != 0o444:
            return False, f"served artifact is not world-readable: {path.relative_to(root)} mode={mode:o}"

    missing_refs = _missing_local_references(root, html_files + css_files)
    if missing_refs:
        return False, f"served output has missing local references: {missing_refs[0]}"

    content_path = root / "content.json"
    if not content_path.is_file():
        return False, "project is missing content.json"
    public_text_files = html_files + css_files + js_files + [root / name for name in ("robots.txt", "sitemap.xml")]
    public_text = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in public_text_files)
    for path in public_text_files + [content_path]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        match = _PLACEHOLDER_RE.search(text)
        if match:
            return False, f"unresolved template placeholder in {path.relative_to(root)}: {match.group(0)}"

    content = _read_json(content_path) or {}
    site_meta = content.get("site") if isinstance(content.get("site"), dict) else content
    language = str((site_meta or {}).get("language") or "").lower()
    if language.startswith("zh"):
        for page_path in html_files:
            page = page_path.relative_to(root).as_posix()
            html = page_path.read_text(encoding="utf-8", errors="ignore")
            visible = _visible_html_text(html)
            demo = _TEMPLATE_VISIBLE_RE.search(visible)
            if demo:
                return False, f"visible template content remains in {page}: {demo.group(0)}"
            if len(re.findall(r"[\u4e00-\u9fff]", visible)) < 12:
                return False, f"{page} has insufficient localized visible content for language={language}"
            for image_tag in re.findall(r"<img\b[^>]*>", html, re.I):
                src_match = re.search(r"\bsrc=[\"']([^\"']+)", image_tag, re.I)
                alt_match = re.search(r"\balt=[\"']([^\"']*)", image_tag, re.I)
                src = src_match.group(1) if src_match else ""
                alt = alt_match.group(1).strip() if alt_match else ""
                if not alt and not re.search(r"aria-hidden=[\"']true", image_tag, re.I):
                    return False, f"{page} has an image without alt text: {src or '<unknown>'}"
                if alt and not re.search(r"[\u4e00-\u9fff]", alt):
                    return False, f"{page} image alt text is not localized: {alt}"
                if _TEMPLATE_IMAGE_RE.search(src):
                    return False, f"{page} still references a default template image: {src}"
        articles = content.get("articles")
        if isinstance(articles, list):
            seen_images = set()
            for index, article in enumerate(articles, 1):
                if not isinstance(article, dict):
                    return False, f"content.json article {index} is not an object"
                image = article.get("image") or article.get("image_path") or article.get("imagePath")
                if not isinstance(image, str) or not image.strip():
                    return False, f"content.json article {index} is missing its image mapping"
                if image in seen_images:
                    return False, f"content.json reuses an article image mapping: {image}"
                seen_images.add(image)

    for page_path in html_files:
        page = page_path.relative_to(root).as_posix()
        html = page_path.read_text(encoding="utf-8", errors="ignore")
        lower = html.lower()
        is_custom_error_page = page_path == root / "404.html"
        if not re.search(r"<title[^>]*>[^<]+</title>", html, re.I):
            return False, f"{page} is missing a non-empty title"
        if not re.search(r"<meta[^>]*name=[\x22\x27]description[\x22\x27]", html, re.I):
            return False, f"{page} is missing description metadata"
        # A custom 404 is an error document, not an indexable publishing
        # route. Requiring canonical/OG metadata here makes a valid error
        # page point at a fake canonical URL (or the homepage), and caused
        # otherwise complete free-template sites to fail the final gate.
        if not is_custom_error_page:
            if not re.search(r"<link[^>]*canonical", html, re.I):
                return False, f"{page} is missing canonical metadata"
            if not re.search(r"<meta[^>]*property=[\x22\x27]og:title[\x22\x27]", html, re.I):
                return False, f"{page} is missing Open Graph metadata"
        if not re.search(r"<link[^>]*rel=[\x22\x27]icon[\x22\x27]", html, re.I):
            return False, f"{page} is missing favicon metadata"
        if "<h1" not in lower:
            return False, f"{page} is missing a primary heading"

    receipt = _read_json(_receipt_path(root)) or {}
    if receipt.get("source_catalog") == FIXED_TEMPLATE_CATALOG_ID and not re.search(
        r"Designed\s+by(?:\s+|<[^>]+>)*BootstrapMade", public_text, re.I
    ):
        return False, "BootstrapMade free template footer attribution is missing"

    content = _read_json(root / "content.json") or {}
    identity_values = [str(content.get(key) or "").strip() for key in CONTENT_IDENTITY_KEYS]
    identity_values = [value for value in identity_values if value]
    app_text = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in js_files)
    if identity_values and not all(value in public_text for value in identity_values):
        if not re.search(r"(?:fetch|XMLHttpRequest|content\.json)", app_text, re.I):
            return False, "content.json identity fields are not rendered and app.js does not load content.json"

    manifest_path = root / "docs" / "image-manifest.md"
    if not manifest_path.is_file():
        return False, "docs/image-manifest.md is missing"
    manifest_lines = manifest_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    final_paths = [line.split(":", 1)[1].strip().strip(chr(96) + chr(34)) for line in manifest_lines if line.strip().startswith("- final_path:")]
    if not final_paths:
        for line in manifest_lines:
            cells = [cell.strip() for cell in line.split("|")]
            if len(cells) >= 3 and cells[2] and cells[2].lower() not in {"image", "path", "---"}:
                match = re.search(r"(/[^\s|]+)", cells[2])
                if match:
                    final_paths.append(match.group(1))
    if not final_paths:
        manifest_text = manifest_path.read_text(encoding="utf-8", errors="ignore")
        if "image_policy: no-article-images" not in manifest_text:
            return False, "image manifest has no final_path entries or explicit no-article-images policy"

    for raw_path in final_paths:
        candidate = _resolved(raw_path) if raw_path.startswith("/home/") else _resolved(root / raw_path.lstrip("/"))
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError:
            return False, f"image manifest path escapes project root: {raw_path}"
        if not candidate.is_file():
            return False, f"image manifest file is missing: {relative}"
        if relative not in public_text and f"/{relative}" not in public_text:
            return False, f"image manifest asset is not referenced by served output: {relative}"

    robots = (root / "robots.txt").read_text(encoding="utf-8", errors="ignore")
    if "sitemap:" not in robots.lower():
        return False, "robots.txt is missing a Sitemap directive"
    try:
        ET.parse(root / "sitemap.xml")
    except (ET.ParseError, OSError) as exc:
        return False, f"sitemap.xml is invalid: {exc}"
    error_page = (root / "404.html").read_text(encoding="utf-8", errors="ignore").lower()
    if "<h1" not in error_page or not re.search(
        r'href=["\'][^"\']*(?:/|index\\.html)(?:["\'#?])',
        error_page,
    ):
        return False, "404.html is missing a heading or home link"
    return True, "static publishing artifact is complete"


def _project_relative_files(root: Path, value: Any) -> list[str] | None:
    if not isinstance(value, list) or not value:
        return None
    result = []
    for raw in value:
        if not isinstance(raw, str) or not raw.strip():
            return None
        path = Path(raw)
        if path.is_absolute() or '..' in path.parts:
            return None
        candidate = root / path
        if not candidate.is_file():
            return None
        result.append(path.as_posix())
    return result


def _acquisition_method_is_valid(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if normalized == "local-approved-source":
        return True
    if not normalized.startswith("official-"):
        return False
    # Accept descriptive official repository/download values while rejecting
    # bare or unqualified sources.
    source_markers = ("github", "git", "repository", "repo", "download", "clone")
    return any(marker in normalized.split("-") for marker in source_markers)


def _project_relative_dirs(root: Path, value: Any) -> list[str] | None:
    if not isinstance(value, list) or not value:
        return None
    result = []
    for raw in value:
        if not isinstance(raw, str) or not raw.strip():
            return None
        path = Path(raw)
        if path.is_absolute() or '..' in path.parts or not (root / path).is_dir():
            return None
        result.append(path.as_posix())
    return result


def _validate_template_review(root: Path) -> tuple[bool, str]:
    review = _read_json(root / 'docs' / REVIEW_NAME)
    if review is None:
        return False, 'docs/template-review.json is missing or invalid JSON'
    if review.get('status') != 'reviewed':
        return False, 'template review status is not reviewed'
    if not isinstance(review.get('reviewed_at_utc'), str) or not review['reviewed_at_utc'].strip():
        return False, 'template review reviewed_at_utc is required'
    # DOM/CSS/JS/responsive/assets/accessibility/SEO/runtime are advisory review
    # fields. The completion gate validates concrete route, reference, and
    # artifact evidence below instead of requiring every review label to pass.
    checks = review.get('checks')
    if checks is not None and not isinstance(checks, dict):
        return False, 'template review checks must be an object when provided'
    findings = review.get('findings')
    if not isinstance(findings, list):
        return False, 'template review findings must be a list'
    verification = review.get('verification')
    if not isinstance(verification, dict):
        return False, 'template review verification evidence is required'
    if verification.get('missing_local_refs') != []:
        return False, 'template review reports missing local references'
    if verification.get('unresolved_template_tokens') not in ([], 0):
        return False, 'template review reports unresolved template tokens'
    if verification.get('unknown_route_status') not in (404, '404'):
        return False, 'template review did not verify the custom 404 route'
    checked_routes = verification.get('checked_routes')
    if not isinstance(checked_routes, list) or not checked_routes:
        return False, 'template review checked_routes evidence is required'
    route_evidence = {}
    for entry in checked_routes:
        if not isinstance(entry, dict):
            return False, "template review contains invalid checked route evidence"
        raw_route = str(entry.get("route") or "").strip().lower()
        route_class = raw_route
        if route_class in {"/", "/index.html", "index.html"}:
            route_class = "home"
        elif route_class.startswith("/"):
            basename = Path(route_class.rstrip("/")).name
            if basename in PUBLISHING_ROUTE_ALIASES["category.html"]:
                route_class = "category"
            elif basename in PUBLISHING_ROUTE_ALIASES["article.html"] or route_class.startswith("/articles/"):
                route_class = "article"
            elif basename in PUBLISHING_ROUTE_ALIASES["search.html"]:
                route_class = "search"
            elif entry.get("custom_404_body") is True or "missing" in route_class or "404" in route_class:
                route_class = "404"
        status = entry.get("status")
        if status is None:
            status = entry.get("local_preview")
        if route_class not in {"home", "category", "article", "search", "404"}:
            continue
        if status not in (200, "200", 404, "404"):
            return False, f"template review has invalid status for {route_class}"
        route_evidence[route_class] = int(status)
    changed_files = review.get('changed_files')
    if not isinstance(changed_files, list):
        return False, 'template review changed_files must be a list'
    for raw in changed_files:
        if not isinstance(raw, str) or not raw.strip():
            return False, 'template review contains an invalid changed file'
        path = Path(raw)
        if path.is_absolute() or '..' in path.parts or not (root / path).is_file():
            return False, f'template review changed file is invalid: {raw}'
    return True, 'template review is complete'


def validate_nginx_routes(root: Path, data: dict[str, Any], review: dict[str, Any]) -> tuple[bool, str]:
    """Verify the declared Host-routed statuses against the local nginx server."""
    host = data.get("nginx_server_name")
    verification = review.get("verification") if isinstance(review, dict) else None
    checked_routes = verification.get("checked_routes") if isinstance(verification, dict) else None
    if not isinstance(host, str) or not host.strip() or not isinstance(checked_routes, list):
        return False, "nginx route evidence is missing"
    route_evidence = {}
    for entry in checked_routes:
        if not isinstance(entry, dict):
            continue
        raw_route = str(entry.get("route") or "").strip().lower()
        route_class = raw_route
        path = entry.get("path")
        if raw_route in {"/", "/index.html", "index.html"}:
            route_class = "home"
        elif raw_route.startswith("/"):
            basename = Path(raw_route.rstrip("/")).name
            if basename in PUBLISHING_ROUTE_ALIASES["category.html"]:
                route_class = "category"
            elif basename in PUBLISHING_ROUTE_ALIASES["article.html"] or raw_route.startswith("/articles/"):
                route_class = "article"
            elif basename in PUBLISHING_ROUTE_ALIASES["search.html"]:
                route_class = "search"
            elif entry.get("custom_404_body") is True or "missing" in raw_route or "404" in raw_route:
                route_class = "404"
        if route_class not in {"home", "category", "article", "search", "404"}:
            continue
        if not isinstance(path, str) or not path.startswith("/"):
            path = raw_route if raw_route.startswith("/") else {
                "home": "/",
                "category": "/category.html",
                "article": "/articles/neutral-pen-testing.html",
                "search": "/search-results.html",
                "404": "/definitely-missing-route",
            }[route_class]
        expected = entry.get("nginx_host")
        if expected is None:
            expected = entry.get("status")
        if expected is None:
            expected = entry.get("local_preview")
        if expected not in (200, "200", 404, "404"):
            return False, f"invalid nginx route evidence for {route_class}"
        route_evidence[route_class] = (path, int(expected))
    for route_class, (path, expected) in route_evidence.items():
        try:
            connection = http.client.HTTPConnection("127.0.0.1", 80, timeout=3)
            connection.request("GET", path, headers={"Host": host})
            response = connection.getresponse()
            actual = response.status
            response.read()
            connection.close()
        except OSError as exc:
            return False, f"nginx Host route check failed for {route_class}: {exc}"
        if actual != expected:
            return False, f"nginx Host route mismatch for {route_class}: expected {expected}, got {actual}"
    return True, "nginx Host routes verified"


def validate_nginx_handoff(root: Path, data: dict[str, Any]) -> tuple[bool, str]:
    """Require an actual enabled nginx server block for the materialized site."""
    host = data.get('nginx_server_name')
    config_raw = data.get('nginx_config_path')
    if not isinstance(host, str) or not host.strip():
        return False, 'nginx_server_name is required before completion'
    if data.get('nginx_test_passed') is not True or data.get('nginx_reloaded') is not True:
        return False, 'nginx -t and nginx reload must both be recorded as successful'
    if not isinstance(config_raw, str) or not config_raw.strip():
        return False, 'nginx_config_path is required before completion'
    config = _resolved(config_raw)
    try:
        config.relative_to(Path('/etc/nginx/sites-available'))
    except ValueError:
        return False, 'nginx_config_path must be under /etc/nginx/sites-available'
    if not config.is_file():
        return False, f'nginx config is missing: {config}'
    try:
        config_text = config.read_text(encoding='utf-8', errors='ignore')
    except OSError as exc:
        return False, f'nginx config is unreadable: {exc}; install the enabled server block with mode 0644'
    if not re.search(rf'\bserver_name\s+[^;]*\b{re.escape(host)}\b', config_text):
        return False, 'nginx config does not declare the recorded server_name'
    if not re.search(rf'\broot\s+{re.escape(str(root))};', config_text):
        return False, 'nginx config does not point to the materialized project root'
    enabled = Path('/etc/nginx/sites-enabled') / config.name
    if not enabled.exists():
        return False, f'nginx config is not enabled: {enabled}'
    return True, 'nginx handoff is configured'


def _validate_free_template_materialization(
    root: Path, data: dict[str, Any], *, require_utilities: bool, verify_snapshot: bool = False
) -> tuple[bool, str]:
    if data.get('deployment_mode') != 'copy-only':
        return False, 'deployment_mode must be copy-only'
    if not _same_path(data.get('destination_template_directory', ''), root):
        return False, 'destination_template_directory is not the project root'
    if not isinstance(data.get('selected_template_name'), str) or not data['selected_template_name'].strip():
        return False, 'selected_template_name is required'
    source_url = data.get('source_url')
    source_catalog = data.get('source_catalog')
    source_catalog_count = data.get('source_catalog_template_count')
    license_name = data.get('license')
    license_url = data.get('license_url')
    if not isinstance(source_url, str) or not re.match(r'https?://\S+', source_url):
        return False, 'source_url must be an official HTTP(S) source'
    parsed_source = urlparse(source_url)
    if parsed_source.hostname not in {FIXED_TEMPLATE_CATALOG_HOST, f"www.{FIXED_TEMPLATE_CATALOG_HOST}"}:
        return False, 'source_url must come from the fixed BootstrapMade official catalog'
    if source_catalog != FIXED_TEMPLATE_CATALOG_ID:
        return False, f'source_catalog must be {FIXED_TEMPLATE_CATALOG_ID}'
    if not isinstance(source_catalog_count, int) or source_catalog_count < FIXED_TEMPLATE_MIN_COUNT:
        return False, f'source_catalog_template_count must be at least {FIXED_TEMPLATE_MIN_COUNT}'
    if not isinstance(license_name, str) or not license_name.strip():
        return False, 'license is required for a free template'
    if not isinstance(license_url, str) or not re.match(r'https?://\S+', license_url):
        return False, 'license_url must be an HTTP(S) license reference'
    if not _acquisition_method_is_valid(data.get('acquisition_method')):
        return False, 'acquisition_method must identify an official or approved source'
    template_files = _project_relative_files(root, data.get('template_files'))
    if template_files is None:
        return False, 'template_files must list copied HTML/CSS/JS files'
    if not any(path.endswith('.html') for path in template_files):
        return False, 'template_files must include HTML'
    if not any(path.endswith('.css') for path in template_files):
        return False, 'template_files must include CSS'
    if not any(path.endswith('.js') for path in template_files):
        return False, 'template_files must include JavaScript'
    source_html_routes = [path for path in template_files if path.lower().endswith(".html")]
    route_paths, route_error = _resolve_publishing_routes(root, source_html_routes)
    if route_error:
        adaptations, adaptation_error = _route_adaptation_plan(root, source_html_routes, data)
        if adaptation_error:
            return False, adaptation_error
        if not adaptations:
            return False, route_error
        route_paths = []
    else:
        adaptations, adaptation_error = _route_adaptation_plan(root, source_html_routes, data)
        if adaptation_error:
            return False, adaptation_error
    adapted_html_routes = [entry["target_file"] for entry in adaptations if (root / entry["target_file"]).is_file()]
    source_hashes = data.get('source_snapshot_sha256')
    if not isinstance(source_hashes, dict):
        return False, 'source_snapshot_sha256 is required'
    source_directory_raw = data.get('source_template_directory') or data.get('staged_source_directory')
    source_directory = _resolved(source_directory_raw) if isinstance(source_directory_raw, str) and source_directory_raw.strip() else None
    if verify_snapshot:
        if source_directory is None or not _is_free_staging_path(source_directory):
            return False, 'source_template_directory must be an official source staging path'
        if not source_directory.is_dir():
            return False, 'source_template_directory is missing before materialization'
    for path in template_files:
        if not isinstance(source_hashes.get(path), str) or not _SHA256_RE.fullmatch(source_hashes[path]):
            return False, f'source_snapshot_sha256 is missing {path}'
        if verify_snapshot:
            source_path = source_directory / path
            if not source_path.is_file():
                return False, f'staged source file is missing: {path}'
            if _sha256(source_path) != source_hashes[path]:
                return False, f'source snapshot mismatch in staging: {path}'
            if _sha256(root / path) != source_hashes[path]:
                return False, f'source snapshot mismatch before materialization: {path}'
    asset_roots = _project_relative_dirs(root, data.get('asset_roots'))
    if asset_roots is None:
        return False, 'asset_roots must list the copied template asset directories'
    if not isinstance(data.get('materialized_at_utc'), str) or not data['materialized_at_utc'].strip():
        return False, 'materialized_at_utc is required'
    if not isinstance(data.get('attempted_candidates'), list) or not data['attempted_candidates']:
        return False, 'attempted_candidates must record the source selection attempt'
    if require_utilities:
        review_valid, review_reason = _validate_template_review(root)
        if not review_valid:
            return False, review_reason
        html_routes = source_html_routes + adapted_html_routes
        artifact_valid, artifact_reason = validate_publishing_artifact(
            root, asset_roots=asset_roots, html_routes=html_routes
        )
        if not artifact_valid:
            return False, artifact_reason
        nginx_valid, nginx_reason = validate_nginx_handoff(root, data)
        if not nginx_valid:
            return False, nginx_reason
        review = _read_json(root / 'docs' / REVIEW_NAME) or {}
        route_valid, route_reason = validate_nginx_routes(root, data, review)
        if not route_valid:
            return False, route_reason
    return True, 'free template is materialized and reviewed'


def validate_materialization(
    project_root: str | Path,
    manifest: dict[str, Any] | None = None,
    *,
    require_utilities: bool = True,
    verify_snapshot: bool | None = None,
) -> tuple[bool, str]:
    """Validate a materialization receipt and the copied shell on disk."""
    root = _resolved(project_root)
    data = manifest if manifest is not None else _read_json(_receipt_path(root))
    if verify_snapshot is None:
        verify_snapshot = manifest is not None
    if data is None:
        return False, "docs/template-materialization.json is missing or invalid JSON"

    if data.get("status") != "materialized":
        return False, "materialization status is not materialized"
    execution_mode = data.get("execution_mode")
    if execution_mode == FREE_EXECUTION_MODE:
        return _validate_free_template_materialization(
            root, data, require_utilities=require_utilities, verify_snapshot=bool(verify_snapshot)
        )
    if execution_mode == LEGACY_EXECUTION_MODE:
        return (
            False,
            "package-only materialization is retired; the 30 local templates are archive-only. "
            "Use free-template-review with an HTML/CSS/JS source extracted from the approved local BootstrapMade ZIP bundle."
        )
    if execution_mode != FREE_EXECUTION_MODE:
        return False, "execution_mode must be free-template-review"
    return _validate_free_template_materialization(
        root, data, require_utilities=require_utilities, verify_snapshot=bool(verify_snapshot)
    )


def _is_shell_path(path: str | Path, root: Path) -> bool:
    target = _resolved(path)
    return target.parent == root and target.name in REQUIRED_FILES


def validate_project_write(path: str | Path, content: str) -> str | None:
    target = _resolved(path)
    root = project_root_for(target)
    if root is None or _path_is_receipt(target, root):
        return None
    valid, reason = validate_materialization(root, require_utilities=False)
    if not valid:
        return f"Blocked static-site project write: {reason}"
    if not _is_shell_path(target, root):
        return None
    receipt = _read_json(_receipt_path(root)) or {}
    if receipt.get('execution_mode') == FREE_EXECUTION_MODE:
        return None
    source = _package_for_number(receipt.get("selected_number"))
    if source is None:
        return "Blocked static-site shell write: selected local package is unavailable."
    name = target.name
    if name.endswith(".html"):
        unchanged = _html_shell_signature_text(content) == _html_shell_signature(source / name)
    elif name == "app.js":
        unchanged = _js_shell_signature_text(content) == _js_shell_signature(source / name)
    elif name == "content.json":
        try:
            json.loads(content)
            unchanged = True
        except (TypeError, json.JSONDecodeError):
            return "Blocked static-site content write: content.json must remain valid JSON."
    else:
        unchanged = hashlib.sha256(content.encode("utf-8")).hexdigest() == _sha256(source / name)
    if not unchanged:
        return f"Blocked static-site shell mutation: {name} may only receive permitted substitutions that preserve the package shell."
    return None


def validate_patch_replace(path: str | Path, old_string: str, new_string: str, replace_all: bool) -> str | None:
    target = _resolved(path)
    root = project_root_for(target)
    if root is None or not _is_shell_path(target, root):
        return None
    try:
        current = target.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return f"Blocked static-site shell patch: cannot read authenticated target ({exc})."
    if old_string not in current:
        return None
    proposed = current.replace(old_string, new_string) if replace_all else current.replace(old_string, new_string, 1)
    return validate_project_write(target, proposed)


def guard_external_reference_read(function_name: str, args: dict[str, Any], session_cwd: str | None = None) -> str | None:
    """Stop reference/browser reads from becoming a pre-materialization shell source."""
    if function_name not in {"web_extract", "browser_navigate"}:
        return None
    values: list[str] = []
    for key in ("url", "urls", "uri", "href"):
        raw = args.get(key)
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, (list, tuple)):
            values.extend(value for value in raw if isinstance(value, str))
    if any("/home/shen/dev" in value for value in values):
        return "Blocked reference read: local /home/shen/dev project paths are never browser or extraction inputs."
    if any(unmanaged_home_project_for(value) is not None for value in values):
        return "Blocked reference read: home-level project paths are not valid template sources; use /home/shen/dev."
    # Official template pages may validate license metadata, but the copied shell must come from the approved local ZIP bundle.
    # Local /home/shen/dev content remains blocked above, so an existing project cannot become the source.
    return None


def guard_nginx_backup_path(command: str) -> str | None:
    """Keep backup files out of nginx include directories."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return "Blocked nginx operation: command quoting is invalid."
    if not any(token in {"cp", "mv", "install", "tee"} for token in tokens):
        return None
    for token in tokens:
        normalized = token.rstrip("/")
        if not re.search(r"/etc/nginx/(?:sites-enabled|conf\.d)/", normalized):
            continue
        name = Path(normalized).name.lower()
        if re.search(r"(?:backup|\.bak(?:\Z|[.-])|\.old(?:\Z|[.-])|~\Z)", name):
            return "Blocked nginx backup placement: keep backups outside sites-enabled/conf.d so they cannot become active server configs."
    return None


def validate_nginx_output(command: str, output: str) -> str | None:
    """Turn nginx duplicate-host warnings into a hard verification failure."""
    if not re.match(r"^\s*(?:sudo\s+)?nginx\s+-[tT]\b", command or ""):
        return None
    if re.search(r"conflicting server name", output or "", re.I):
        return "Nginx validation failed: conflicting server_name warning detected; remove the duplicate include or backup and rerun nginx -t/-T."
    return None


def _path_is_receipt(path: Path, root: Path) -> bool:
    return path == _receipt_path(root)


def guard_path(path: str | Path, operation: str) -> str | None:
    """Return a blocking error for a file-tool operation, or ``None``."""
    target = _resolved(path)
    target_root = project_root_for(target)
    if operation == "write" and target_root is not None:
        try:
            from tools.skill_provenance import is_background_review
            if is_background_review() and _receipt_path(target_root).is_file():
                return (
                    "Blocked background skill review: authenticated static-site projects are "
                    "read-only; update the skill library only."
                )
        except Exception:
            pass
    turn_error = _static_site_turn_guard(target_root)
    if turn_error and not (
        operation == "write"
        and target_root is not None
        and _path_is_receipt(target, target_root)
    ):
        return turn_error
    if operation == "write" and _is_local_template_bundle_path(target):
        return "Blocked: user-provided BootstrapMade ZIP bundle is immutable and read-only."
    template_root = template_source_for(target)
    if template_root is not None and operation == "write":
        return "Blocked: local numbered template packages are immutable and read-only."
    if operation == "write" and _FORBIDDEN_GENERATOR_RE.search(target.as_posix()):
        return "Blocked: materialized static-site publishing forbids generators, renderers, and population helper scripts."
    if operation == "write" and _unapproved_tmp_static_path(target):
        return (
            "Blocked: static-site files may not be authored under arbitrary /tmp paths; "
            "use /tmp/hermes-free-templates/<slug> only for the official source staging copy."
        )

    if target == DEV_ROOT:
        return "Blocked: /home/shen/dev contents are unavailable before a valid project materialization receipt."

    unmanaged_root = unmanaged_home_project_for(path)
    if unmanaged_root is not None:
        return "Blocked: static-site projects must be created under /home/shen/dev/<site-name>."

    root = project_root_for(path)
    if root is None:
        return None

    # Existing-site SEO maintenance uses the site's own source/build/publish
    # workflow. It is not a new-template materialization operation.
    if is_authorized_existing_seo_project(root) and operation in {"read", "write"}:
        return None

    target = _resolved(path)
    if operation == "read":
        if _path_is_receipt(target, root):
            valid, reason = validate_materialization(root, require_utilities=False)
            if valid:
                return None
            return (
                "Blocked static-site project read: an existing or stale materialization receipt "
                f"is unavailable before authenticated materialization ({reason})."
            )
        valid, reason = validate_materialization(root, require_utilities=False)
        if not valid:
            return (
                "Blocked static-site project read: existing project pages/assets and "
                f"instructions are unavailable before materialization ({reason}). "
                "Only directory existence and nginx host-conflict checks are allowed."
            )
        return None

    if operation == "write":
        if _path_is_receipt(target, root):
            return None
        if _FORBIDDEN_GENERATOR_RE.search("/" + target.name):
            return "Blocked: materialized static-site publishing forbids generators, renderers, and population helper scripts."
        valid, _ = validate_materialization(root, require_utilities=False)
        if not valid:
            return (
                "Blocked static-site project write before materialization. Copy one numbered "
                "package and write a valid materialization receipt first."
            )
        return None

    return None


def _receipt_field_error_is_recoverable(reason: str) -> bool:
    return reason.startswith((
        "materialization status is not materialized",
        "template_files must list",
        "template_files must include",
        "source_snapshot_sha256 is required",
        "source_template_directory must be",
        "source_template_directory is missing",
        "asset_roots must list",
        "attempted_candidates must record",
        "materialized_at_utc is required",
        "route_adaptations must",
        "route_adaptations contains",
        "route_adaptations source",
        "route_adaptations method",
    ))


def prepare_receipt_content(path: str | Path, content: str) -> str:
    target = _resolved(path)
    root = project_root_for(target)
    if root is None or not _path_is_receipt(target, root):
        return content
    try:
        data = json.loads(content)
    except (TypeError, json.JSONDecodeError):
        return content
    if not isinstance(data, dict) or data.get("execution_mode") != FREE_EXECUTION_MODE:
        return content
    raw_source = data.get("source_template_directory") or data.get("staged_source_directory")
    source = _resolved(raw_source) if isinstance(raw_source, str) and raw_source.strip() else None
    if source is None or not _is_free_staging_path(source) or not source.is_dir():
        return content
    actual_source = _discover_staged_template_root(source)
    if not actual_source.is_dir():
        return content
    files = _staged_template_files(actual_source)
    if not files:
        files = data.get("template_files")
    if not isinstance(files, list) or not files:
        return content
    changed = False
    if data.get("template_files") != files:
        data["template_files"] = files
        changed = True
    if source != actual_source:
        data["source_template_directory"] = str(actual_source)
        source = actual_source
        changed = True
    html_routes = [
        Path(raw).as_posix()
        for raw in files
        if isinstance(raw, str) and raw.lower().endswith(".html") and (source / raw).is_file()
    ]
    planned_adaptations = _automatic_route_adaptations(source, html_routes)
    if data.get("route_adaptations") != planned_adaptations:
        data["route_adaptations"] = planned_adaptations
        changed = True
    hashes = data.get("source_snapshot_sha256")
    if not isinstance(hashes, dict):
        hashes = {}
        data["source_snapshot_sha256"] = hashes
    for raw in files:
        if not isinstance(raw, str) or not raw or Path(raw).is_absolute():
            continue
        source_file = source / raw
        if source_file.is_file() and source_file.suffix.lower() in {".html", ".css", ".js"}:
            digest = _sha256(source_file)
            if hashes.get(raw) != digest:
                hashes[raw] = digest
                changed = True
    if data.get("source_template_directory") != str(source):
        data["source_template_directory"] = str(source)
        changed = True
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n" if changed else content
def _staged_candidate_route_error(data: dict[str, Any]) -> str | None:
    raw_source = data.get("source_template_directory") or data.get("staged_source_directory")
    if not isinstance(raw_source, str) or not raw_source.strip():
        return None
    source = _resolved(raw_source)
    if not _is_free_staging_path(source) or not source.is_dir():
        return "source_template_directory must be an official source staging path"
    source = _discover_staged_template_root(source)
    if not (source / "index.html").is_file():
        return "staged source must have index.html at its materialization root"
    html_routes = [
        path.relative_to(source).as_posix()
        for path in source.rglob("*.html")
        if "node_modules" not in path.parts and "docs" not in path.parts
    ]
    if not html_routes:
        return "staged source must include HTML files"
    if not any(path.suffix.lower() == ".css" for path in source.rglob("*.css")):
        return "staged source must include CSS files"
    if not any(path.suffix.lower() == ".js" for path in source.rglob("*.js")):
        return "staged source must include JavaScript files"
    return None


def validate_receipt_write(path: str | Path, content: str) -> str | None:
    """Validate a receipt before allowing its first materialization write."""
    target = _resolved(path)
    root = project_root_for(target)
    if root is None or not _path_is_receipt(target, root):
        return None
    try:
        data = json.loads(content)
    except (TypeError, json.JSONDecodeError) as exc:
        return f"Blocked materialization receipt: invalid JSON ({exc})"
    existing_receipt = _read_json(_receipt_path(root))
    copied_shell = (
        (root / "index.html").is_file()
        and any(
            path.is_file()
            for path in root.rglob("*.css")
            if "docs" not in path.parts and "node_modules" not in path.parts
        )
        and any(
            path.is_file()
            for path in root.rglob("*.js")
            if "docs" not in path.parts and "node_modules" not in path.parts
        )
    )
    # A receipt cannot authenticate a copy that has not happened yet. Keep
    # every pre-copy receipt attempt recoverable, including status=materialized
    # with a bad/incomplete manifest, so the guarded direct cp can still run.
    # Once the copied shell exists, normal receipt validation becomes
    # fail-closed again.
    if not isinstance(existing_receipt, dict) and not copied_shell:
        return (
            "Blocked materialization receipt: copy the staged template into the "
            "fresh project root first; the first accepted receipt requires the "
            "copied HTML/CSS/JS shell."
        )
    if isinstance(data, dict):
        candidate_error = _staged_candidate_route_error(data)
        if candidate_error:
            _fail_static_site_turn(root, candidate_error)
            return (
                f"BLOCKED: staged template candidate rejected for {root}: {candidate_error}. "
                "Reject this candidate before materialization; do not copy or synthesize routes."
            )
    verify_snapshot = not (isinstance(existing_receipt, dict) and existing_receipt.get("status") == "materialized")
    valid, reason = validate_materialization(root, data if isinstance(data, dict) else None, require_utilities=False, verify_snapshot=verify_snapshot)
    if not valid:
        if _receipt_field_error_is_recoverable(reason):
            return (
                f"Blocked materialization receipt for {root}: {reason}. "
                "Correct only this receipt using the staged source manifest. Set status=materialized and keep the canonical field names; do not use aliases or alter project files until this receipt is accepted."
            )
        _fail_static_site_turn(root, reason)
        return (
            f"BLOCKED: materialization receipt rejected for {root}: {reason}. "
            "Stop this turn; do not switch project roots or templates."
        )
    _clear_static_site_turn_recovery(root)
    return None


def guard_image_generation_args(args: dict[str, Any]) -> str | None:
    """Block image generation from using pre-materialization project assets."""
    for key in ("image_url", "reference_image_urls"):
        raw = args.get(key)
        values = raw if isinstance(raw, (list, tuple)) else [raw]
        for value in values:
            if not isinstance(value, str) or not value.strip():
                continue
            candidate = value.strip()
            if candidate.startswith(("http://", "https://", "data:")):
                continue
            error = guard_path(candidate, "read")
            if error:
                return f"Blocked image_generate source: {error}"
    return None


def guard_execute_code(code: str, session_cwd: str | None = None) -> str | None:
    """Prevent execute_code from bypassing file and terminal policy hooks."""
    if _unapproved_tmp_static_operation(code or ""):
        return (
            "Blocked execute_code: static-site files must stay in the approved "
            "/tmp/hermes-free-templates source staging path; arbitrary /tmp generation is forbidden."
        )
    if str(SITES_ROOT) in (code or "") and any(
        marker in (code or "") for marker in ("write_text", "write_bytes", "open(", "subprocess", "os.system", "os.popen")
    ):
        return "Blocked execute_code: local numbered template packages are immutable and read-only."

    if session_cwd and template_source_for(session_cwd) is not None and any(
        marker in (code or "") for marker in ("write_text", "write_bytes", "open(", "subprocess", "os.system", "os.popen")
    ):
        return "Blocked execute_code: local numbered template packages are immutable and read-only."

    if _FORBIDDEN_GENERATOR_RE.search(code or ""):
        return "Blocked: materialized static-site publishing forbids generators, renderers, and population helper scripts."

    session_root = project_root_for(session_cwd) if session_cwd else None
    try:
        from tools.skill_provenance import is_background_review
        if is_background_review():
            candidate_roots = set()
            if session_root is not None:
                candidate_roots.add(session_root)
            for token in re.findall(r"/home/shen/dev/[^\s\"\x27;&|()<>]+", code or ""):
                candidate_root = project_root_for(token)
                if candidate_root is not None:
                    candidate_roots.add(candidate_root)
            if any(_receipt_path(candidate).is_file() for candidate in candidate_roots):
                return (
                    "Blocked background skill review: authenticated static-site projects are "
                    "read-only; update the skill library only."
                )
    except Exception:
        pass
    nested_terminal = bool(re.search(
        r"(?:from\s+hermes_tools\s+import\s+terminal|(?:hermes_tools\.)?terminal\s*\()",
        code or "",
        re.I,
    ))
    if nested_terminal and (
        session_root is not None
        or (session_cwd and _in_dev_scope(session_cwd))
        or str(DEV_ROOT) in (code or "")
    ):
        return (
            "Blocked execute_code: nested terminal calls cannot mutate or copy "
            "static-site project roots; use the guarded top-level terminal tool."
        )
    if session_cwd and unmanaged_home_project_for(session_cwd) is not None:
        return "Blocked execute_code: static sites must live under /home/shen/dev."
    referenced_home_paths = re.findall(r"/home/shen/[^\s\"\x27;&|()<>]+", code or "")
    if any(unmanaged_home_project_for(raw) is not None for raw in referenced_home_paths):
        return "Blocked execute_code: static sites must live under /home/shen/dev."
    if str(DEV_ROOT) in (code or ""):
        referenced_roots = {project_root_for(token) for token in re.findall(r"/home/shen/dev/[^\s\"\x27;&|()<>]+", code or "")}
        referenced_roots.discard(None)
        if session_root is None or any(root != session_root for root in referenced_roots):
            return "Blocked execute_code: existing /home/shen/dev project content is outside the active authenticated static-site scope."

    root = project_root_for(session_cwd) if session_cwd else None
    if root is None:
        return None
    valid, reason = validate_materialization(root, require_utilities=False)
    lowered = (code or "").lower()
    receipt_mode = (_read_json(_receipt_path(root)) or {}).get('execution_mode')
    if valid and receipt_mode != FREE_EXECUTION_MODE and any(
        re.search(rf"(?<![A-Za-z0-9_-]){re.escape(name.lower())}(?![A-Za-z0-9_-])", lowered)
        for name in REQUIRED_FILES
    ) and any(marker in lowered for marker in ("write_text", "write_bytes", "open(", "subprocess", "os.system", "os.popen")):
        return "Blocked execute_code: authenticated package shell files require the shell-preserving file-write contract."
    if not valid and any(marker in lowered for marker in (
        "open(", "read_text", "write_text", "read_bytes", "write_bytes",
        "subprocess", "os.system", "os.popen", "exec(", "terminal(",
        "hermes_tools", "shutil", "copytree", "copy(", "move(", "makedirs",
    )):
        return f"Blocked execute_code in static-site project: project content and generated outputs are unavailable before materialization ({reason})."
    return None

def _fixed_catalog_acquisition_error(
    command: str, workdir: str | None = None, session_cwd: str | None = None
) -> str | None:
    """Keep staging acquisition inside the fixed BootstrapMade catalog."""
    locations = [command or "", workdir or "", session_cwd or ""]
    in_fixed_staging = any(
        "/tmp/hermes-free-templates" in value
        or _is_free_staging_path(value)
        for value in locations
    )
    if not in_fixed_staging:
        return None
    urls = re.findall(r"https?://[^\s'\";&|()<>]+", command or "")
    acquisition_command = bool(
        re.search(r"\b(?:git\s+clone|curl|wget)\b", command or "", re.I)
        or (urls and re.search(r"(?:urllib|requests|urlopen|download|clone|fetch)", command or "", re.I))
    )
    if not acquisition_command:
        return None
    for raw in urls:
        host = urlparse(raw).hostname
        if host not in {FIXED_TEMPLATE_CATALOG_HOST, f"www.{FIXED_TEMPLATE_CATALOG_HOST}"}:
            return (
                "Blocked template acquisition: new sites use only the fixed "
                "BootstrapMade free catalog. Do not clone or download another "
                "GitHub or marketplace template."
            )
    return None


def _pre_materialization_source_error(command: str, cwd: str | None) -> str | None:
    """Reject an unsuitable staged source before it can be copied.

    The source must be an official staged HTML/CSS/JS tree. Missing publishing
    pages are recorded for post-receipt adaptation; paid-license-only sources
    are still rejected before any project copy.
    """
    normalized = re.sub(
        r"^\s*set\s+-[A-Za-z]+\s*(?:;|&&|\n)\s*", "", command or "", count=1
    )
    try:
        tokens = shlex.split(normalized)
    except ValueError:
        return "Blocked pre-materialization source: command quoting is invalid; select another source."
    if tokens and tokens[0] == "sudo":
        tokens = tokens[1:]
    if not tokens or tokens[0] not in {"cp", "install"}:
        return None
    operands = [token for token in tokens[1:] if not token.startswith("-")]
    if len(operands) < 2:
        return None
    base = _resolved(cwd or Path.cwd())
    for raw in operands[:-1]:
        source = _resolved(raw) if raw.startswith("/") else _resolved(base / raw)
        if not _is_free_staging_path(source) or not source.is_dir():
            continue
        actual_source = _discover_staged_template_root(source)
        if actual_source != source:
            return (
                "Blocked pre-materialization source: staging contains a nested template root. "
                f"Copy {actual_source}/. directly; no project files were copied."
            )
        html_routes = [
            path.relative_to(source).as_posix()
            for path in source.rglob("*.html")
            if "node_modules" not in path.parts and "docs" not in path.parts
        ]
        # Only validate the tree that the copy command actually targets.
        # Wrapper directories such as an archive containing ``unpacked/`` are
        # resolved by the acquisition step before this preflight.
        if not (source / "index.html").is_file():
            continue
        # A not-yet-populated staging placeholder cannot be judged here;
        # the receipt gate remains responsible for rejecting it after copy.
        if not html_routes:
            continue
        if not any(path.suffix.lower() == ".css" for path in source.rglob("*.css")):
            return "Blocked pre-materialization source: staged source has no CSS files; no project files were copied."
        if not any(path.suffix.lower() == ".js" for path in source.rglob("*.js")):
            return "Blocked pre-materialization source: staged source has no JavaScript files; no project files were copied."
        source_text = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in source.rglob("*")
            if path.is_file() and path.suffix.lower() in {".html", ".md", ".json", ".txt"}
            and "node_modules" not in path.parts
        )
        if re.search(
            r"must\s+have\s+a\s+valid\s+license|valid\s+license\s+from\s+official\s+store|"
            r"purchase\s*:\s*https?://",
            source_text,
            re.I,
        ):
            return (
                "Blocked pre-materialization source: the staged template declares "
                "a paid or separately licensed theme. Re-select an official free "
                "template; no project files were copied."
            )
    return None


def _copy_target_is_bootstrap_clean(root: Path) -> bool:
    """Allow only an empty root or harmless pre-copy receipt scaffolding."""
    if not root.is_dir():
        return False
    try:
        entries = list(root.iterdir())
    except OSError:
        return False
    if not entries:
        return True
    if len(entries) != 1 or entries[0].name != "docs" or not entries[0].is_dir():
        return False
    try:
        docs_entries = list(entries[0].iterdir())
    except OSError:
        return False
    return not docs_entries or (
        len(docs_entries) == 1
        and docs_entries[0].name == RECEIPT_NAME
        and docs_entries[0].is_file()
    )


def _pre_materialization_copy_is_safe(command: str, cwd: str | None) -> bool:
    """Allow copying only approved local/free sources into a new project."""
    normalized_command = re.sub(
        r"^\s*set\s+-[A-Za-z]+\s*(?:;|&&|\n)\s*", "", command or "", count=1
    )
    try:
        tokens = shlex.split(normalized_command)
    except ValueError:
        return False
    if tokens and tokens[0] == "sudo":
        tokens = tokens[1:]
    if not tokens or tokens[0] not in {"cp", "install"}:
        return True
    operands = [token for token in tokens[1:] if not token.startswith("-")]
    if len(operands) < 2:
        return False
    base = _resolved(cwd or Path.cwd())
    local_bundle_copy = False
    for token in operands[:-1]:
        source = _resolved(token) if token.startswith("/") else _resolved(base / token)
        if _in_dev_scope(source):
            return False
        if _is_local_template_bundle_path(source):
            if not source.is_file() or source.suffix.lower() != ".zip":
                return False
            local_bundle_copy = True
        elif not _is_free_staging_path(source):
            return False
    destination = _resolved(operands[-1]) if operands[-1].startswith("/") else _resolved(base / operands[-1])
    if local_bundle_copy and _in_dev_scope(destination):
        return False
    if _in_dev_scope(destination):
        destination_root = project_root_for(destination)
        receipt_target = destination_root / "docs" / RECEIPT_NAME if destination_root else None
        if destination_root is None or (destination != destination_root and destination != receipt_target):
            return False
        if destination_root.exists() and not _copy_target_is_bootstrap_clean(destination_root):
            # The workflow may create an empty destination directory, or leave
            # only the receipt scaffold from a failed pre-copy attempt. Never
            # copy over a partial shell, assets, or arbitrary project files.
            return False
    return True


def _pre_materialization_command_is_safe(command: str, cwd: str | None) -> bool:
    """Allow only metadata/scaffold/free-source-copy command sequences."""
    if _metadata_only_command(command):
        return True
    normalized = re.sub(
        r"^\s*set\s+-[A-Za-z]+\s*(?:;|&&|\n)\s*", "", command or "", count=1
    )
    parts = [part.strip() for part in re.split(r"\s*(?:&&|\|\||[;\n])\s*", normalized) if part.strip()]
    if not parts:
        return False
    saw_copy = False
    for part in parts:
        if re.match(r"^(?:sudo\s+)?(?:cp|install)\b", part):
            if not _pre_materialization_copy_is_safe(part, cwd):
                return False
            saw_copy = True
            continue
        if _pre_materialization_scaffold_safe(part, cwd) or _metadata_only_command(part):
            continue
        return False
    return saw_copy


def _post_materialization_copy_is_safe(command: str, cwd: str | None, root: Path) -> bool:
    """Reject recursive directory copies into an authenticated project root.

    A package is copied once before its receipt is authenticated. After that,
    ``cp -a . <project>/`` is a shell replacement, not a permitted content or
    image substitution, even when the source happens to be the selected local
    package. Recovery must start from a fresh materialization rather than
    silently overwriting a live project shell.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if not tokens or tokens[0] not in {"cp", "install"}:
        return True
    operands = [token for token in tokens[1:] if not token.startswith("-")]
    if len(operands) < 2:
        return False
    recursive = tokens[0] == "cp" and any(
        token in {"-a", "-r", "-R", "--archive", "--recursive"}
        or token.startswith("-a")
        or token.startswith("-r")
        for token in tokens[1:]
    )
    if not recursive:
        return True
    base = _resolved(cwd or Path.cwd())
    destination = _resolved(operands[-1]) if operands[-1].startswith("/") else _resolved(base / operands[-1])
    return destination != root


def _metadata_only_command(command: str) -> bool:
    """Allow only existence/config metadata probes before materialization.

    This is intentionally narrower than a generic read allowlist: ``stat``
    on ``/home/shen/dev/site/index.html`` is a content-boundary bypass even
    though it does not print file bytes, and ``mkdir`` below the project root
    can create a pre-materialization implementation tree.
    """
    normalized = command.strip()
    if not normalized:
        return True
    # Terminal commonly prefixes read-only probes with ``set -eu``. Strip only
    # that shell-safety prefix; it does not grant any additional file access.
    normalized = re.sub(r"^set\s+-[A-Za-z]+\s*(?:;|&&|\n)\s*", "", normalized, count=1)
    # Normalize two read-only compound probes used by the builder before
    # applying the smaller command recognizers below. The first lists only
    # immediate child directories; the second filters nginx's rendered config
    # for one requested server_name. Neither exposes page/assets contents.
    safe_nginx_probe = re.compile(
        r"if\s+command\s+-v\s+nginx(?:\s+>/dev/null\s+2>&1)?\s*;\s*then\s+"
        r"(?:sudo\s+)?nginx\s+-T\s+2>&1\s*\|\s*grep\s+-nE\s+['\"][^'\"]*server_name[^'\"]*['\"]"
        r"\s*(?:\|\|\s*true)?\s*;\s*else\s+(?:printf|echo)\b[^;]*;\s*fi",
        re.I,
    )
    normalized = safe_nginx_probe.sub("printf 'nginx metadata\n'", normalized)
    safe_find_probe = re.compile(
        r"find\s+/home/shen/dev\s+-mindepth\s+1\s+-maxdepth\s+1\s+-type\s+d"
        r"\s+-printf\s+(['\"]).*?\1",
        re.I,
    )
    normalized = safe_find_probe.sub("printf 'dev roots\n'", normalized)
    # Agents often wrap the same root existence/type probe in an if/else
    # block. Allow only fixed-output branches whose condition targets DEV_ROOT
    # or one immediate project directory; never allow nested file paths or
    # commands that can read project contents.
    # Fixed-output shell helpers commonly accompany metadata probes. They do
    # not read project content; reject command substitution, redirection, and
    # known content-reading tools before allowing them.
    if re.match(r"^(?:printf|echo)\b", normalized):
        return not re.search(r"\$\(|`|[<>]\s*|\b(?:cat|head|tail|sed|awk|grep|rg|python|node|find)\b", normalized)
    if normalized == "pwd":
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\$\?", normalized):
        return True
    if normalized.startswith("if "):
        probe = re.sub(r"\s+", " ", normalized.replace("\n", " ").replace("\r", " ")).strip()
        match = re.fullmatch(
            r"if\s+(?:test\s+)?(?:\[\s*)?(?:!\s+)?-[ed]\s+"
            r"(/home/shen/dev(?:/[^/\s;&|()<>]+)?)\s*(?:\])?\s*;\s*then\s+"
            r"(?:(?:printf|echo)\s+[^;&|<>]+)"
            r"(?:\s*;\s*else\s+(?:(?:printf|echo)\s+[^;&|<>]+))?"
            r"\s*;?\s*fi",
            probe,
        )
        if match and not re.search(r"\$\(|`|\b(?:cat|head|tail|sed|awk|grep|rg|python|node|find)\b", probe):
            candidate = _resolved(match.group(1))
            try:
                relative = candidate.relative_to(DEV_ROOT)
            except ValueError:
                return False
            return len(relative.parts) <= 1
        return False
    if re.search(r"(?:^|[\s;&|()])(?:sudo\s+)?nginx\s+-[tT]\b", normalized):
        # Host-conflict checks may inspect nginx's rendered config, but only
        # through a fixed server_name grep. Do not permit arbitrary config
        # dumps or file/content readers in the pre-materialization phase.
        if re.search(r"\b(?:cat|head|tail|less|more|awk|python(?:3)?|node|npm|rm|mv|cp|install|tee|rg)\b|sed\s+-i|\$\(|`", normalized):
            return False
        return bool(re.search(r"\bgrep\b", normalized) and re.search(r"server_name", normalized, re.I))
    if re.search(r"(?:;|&&|\|\||\|)", normalized):
        parts = [part for part in re.split(r"\s*(?:&&|\|\||[;|\n])\s*", normalized) if part]
        return all(_metadata_only_command(part) for part in parts)
    if _FORBIDDEN_GENERATOR_RE.search(normalized) or _WRITE_RE.search(normalized):
        return False
    if re.search(r"\b(?:cat|head|tail|less|more|sed|awk|grep|rg|git\s+(?:show|diff)|python(?:3)?\s+-|node\s+-e)\b", normalized):
        return False
    if re.search(r"\bfind\b", normalized):
        return bool(re.fullmatch(r"find\s+/home/shen/dev(?:\s+-maxdepth\s+1)?\s+-type\s+d(?:\s+-print)?", normalized))
    if re.match(r"^(?:mkdir)\b", normalized):
        try:
            tokens = shlex.split(normalized)
        except ValueError:
            return False
        paths = [token for token in tokens[1:] if not token.startswith('-')]
        if not paths:
            return False
        for raw in paths:
            candidate = _resolved(raw)
            try:
                relative = candidate.relative_to(DEV_ROOT)
            except ValueError:
                continue
            # Scaffolding may create the new project root and its docs folder;
            # assets/public/routes are implementation mutations and are denied.
            if len(relative.parts) > 2 or (len(relative.parts) == 2 and relative.parts[1] != 'docs'):
                return False
        return True
    if not re.match(r"^(?:test|\[|stat|realpath|readlink)\b", normalized):
        return bool(re.match(r"^(?:command\s+-v|which)\b", normalized))
    try:
        tokens = shlex.split(normalized)
    except ValueError:
        return False
    # Metadata probes may target /home/shen/dev itself or one project directory,
    # never a page, asset, docs file, or nested path.
    for raw in tokens[1:]:
        if raw.startswith('/home/shen/dev'):
            candidate = _resolved(raw)
            try:
                relative = candidate.relative_to(DEV_ROOT)
            except ValueError:
                return False
            if len(relative.parts) > 1:
                return False
    return True


def _pre_materialization_scaffold_safe(command: str, cwd: str | None) -> bool:
    """Allow only the empty project/docs directory scaffold before receipt."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if not tokens or tokens[0] != 'mkdir':
        return False
    base = _resolved(cwd or Path.cwd())
    paths = [token for token in tokens[1:] if not token.startswith('-')]
    if not paths:
        return False
    for raw in paths:
        candidate = _resolved(raw) if raw.startswith('/') else _resolved(base / raw)
        root = project_root_for(candidate)
        if root is None:
            continue
        if candidate not in {root, root / 'docs'}:
            return False
    return True


def _template_paths_in_command(command: str, cwd: str | None) -> list[Path]:
    base = _resolved(cwd or Path.cwd())
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []
    paths = []
    for token in tokens:
        if token.startswith("-"):
            continue
        candidate = _resolved(token) if token.startswith("/") else _resolved(base / token)
        if template_source_for(candidate) is not None:
            paths.append(candidate)
    return paths


def guard_terminal_command(
    command: str,
    workdir: str | None = None,
    session_cwd: str | None = None,
) -> str | None:
    """Block terminal reads/builds that would bypass the file-tool gates."""
    command_roots = []
    for candidate in (workdir, session_cwd):
        if candidate:
            root = project_root_for(candidate)
            if root is not None:
                command_roots.append(root)
    for token in re.findall(r"/home/shen/dev/[^\s'\";&|()<>]+", command or ""):
        root = project_root_for(token)
        if root is not None:
            command_roots.append(root)
    try:
        from tools.skill_provenance import is_background_review
        if is_background_review() and any(
            _receipt_path(root).is_file() for root in dict.fromkeys(command_roots)
        ):
            return (
                "Blocked background skill review: authenticated static-site projects are "
                "read-only; update the skill library only."
            )
    except Exception:
        pass
    for root in dict.fromkeys(command_roots):
        turn_error = _static_site_turn_guard(root)
        if turn_error:
            return turn_error

    free_staging = tuple(
        _resolved(candidate)
        for candidate in (workdir, session_cwd)
        if candidate
        and any(
            _resolved(staging) == _resolved(candidate)
            or _resolved(staging) in _resolved(candidate).parents
            for staging in FREE_TEMPLATE_STAGING_ROOTS
        )
    )
    tmp_workdir = any(
        _resolved(candidate).as_posix().startswith("/tmp/")
        and not _is_free_staging_path(candidate)
        for candidate in (workdir, session_cwd)
        if candidate
    )
    fixed_source_error = _fixed_catalog_acquisition_error(command, workdir, session_cwd)
    if fixed_source_error:
        return fixed_source_error
    if _unapproved_tmp_static_operation(command) or (
        tmp_workdir and re.search(r"(?:http\.server|\bzip(?:\s|$))", command, re.I)
    ):
        return (
            "Blocked: static-site staging must use /tmp/hermes-free-templates/<slug>; "
            "arbitrary /tmp project generation, preview, and packaging are not allowed."
        )
    if free_staging and re.search(
        r"(?:npm\s+(?:ci|install|i)(?:\s|$)|pnpm\s+(?:install|i)(?:\s|$)|"
        r"yarn\s+(?:install|add)(?:\s|$)|npm\s+(?:run\s+)?(?:build|bundle)|"
        r"pnpm\s+(?:run\s+)?(?:build|bundle)|yarn\s+(?:run\s+)?(?:build|bundle)|"
        r"(?:vite|webpack|rollup|parcel)(?:\s|$))",
        command,
        re.I,
    ):
        return (
            "Blocked: free-template-review forbids dependency installation and "
            "Vite/webpack/rollup/parcel build commands that regenerate the copied "
            "HTML/CSS/JS shell."
        )
    home_paths = re.findall(r"/home/shen/[^\s'\";&|()<>]+", command or "")
    if any(unmanaged_home_project_for(raw) is not None for raw in home_paths):
        return "Blocked: static-site projects must be created under /home/shen/dev/<site-name>."
    for candidate in (workdir, session_cwd):
        if candidate and unmanaged_home_project_for(candidate) is not None:
            return "Blocked: static-site projects must be created under /home/shen/dev/<site-name>."
    # A command run from DEV_ROOT can read child projects with relative paths
    # even when ``/home/shen/dev`` never appears in the command text.  Treat
    # the development root itself as a protected boundary before any project
    # receipt is authenticated; only the same metadata probes, local package
    # copy, and empty project/docs scaffolding remain allowed.
    root_cwd = _resolved(workdir or session_cwd) if (workdir or session_cwd) else None
    if root_cwd == DEV_ROOT and not _metadata_only_command(command):
        safe_copy = _pre_materialization_command_is_safe(command, workdir or session_cwd)
        safe_scaffold = _pre_materialization_scaffold_safe(command, workdir or session_cwd)
        if not safe_copy and not safe_scaffold:
            if re.search(r"(?:^|[\s;&|()])(?:cp|install)\b", command):
                for raw in re.findall(r"/home/shen/dev/[^\s'\";&|()<>]+", command):
                    candidate_root = project_root_for(raw)
                    if candidate_root is not None and candidate_root.exists():
                        return (
                            "Blocked pre-materialization copy: target project root already exists. "
                            "Choose a fresh /home/shen/dev/<site-name> or stop; do not nest a template inside it."
                        )
            return "Blocked static-site terminal operation: /home/shen/dev child-project contents cannot be read or generated before materialization."
    if re.search(r"(?:^|[\s;&|()])/home/shen/dev(?:/|[\s;&|()]|$)", command) and not _metadata_only_command(command):
        source_error = _pre_materialization_source_error(command, workdir or session_cwd)
        if source_error:
            return source_error
        safe_pre_copy = (
            _pre_materialization_command_is_safe(command, workdir or session_cwd)
        )
        references = re.findall(r"/home/shen/dev(?:/[^\s'\";&|()<>]*)?", command)
        for raw in references:
            root = project_root_for(raw)
            if root is None:
                return "Blocked static-site terminal operation: /home/shen/dev contents cannot be read before materialization."
            if is_authorized_existing_seo_project(root):
                continue
            valid, _ = validate_materialization(root, require_utilities=False)
            if not valid and not safe_pre_copy:
                return "Blocked static-site terminal operation: /home/shen/dev contents cannot be read before materialization."
    template_paths = _template_paths_in_command(command, workdir or session_cwd)
    template_write = bool(
        template_paths
        and (re.search(r"(?:>|>>|tee\b|sed\s+-i|perl\s+-[0-9]*pi|python(?:3)?\s+-|node\s+-e|(?:mkdir|mv|rm)\b)", command)
             or (re.match(r"^(?:cp|install)\b", command.strip()) and template_paths[-1] == _resolved(shlex.split(command)[-1])))
    )
    if template_write:
        return "Blocked: local numbered template packages are immutable and read-only."

    roots = []
    for candidate in (workdir, session_cwd):
        if candidate and project_root_for(candidate) is not None:
            roots.append(project_root_for(candidate))
    for token in re.findall(r"/home/shen/dev/[^\s'\";&|()<>]+", command):
        root = project_root_for(token)
        if root is not None:
            roots.append(root)
    roots = list({root for root in roots if root is not None})
    if not roots:
        return None

    shell_write_command = bool(
        _WRITE_RE.search(command)
        or re.search(r"(?:^|[\s;&|()])(?:cp|install|mv)\b", command)
        or (
            re.search(r"\b(?:python(?:3)?|node|perl|ruby)\b", command)
            and not re.search(r"(?:--check\b|py_compile)", command)
        )
    )
    for root in roots:
        if is_authorized_existing_seo_project(root):
            # Existing-site SEO maintenance follows the site's own documented
            # source/build/publish workflow and does not require new-template
            # materialization. Unknown roots remain fail-closed below.
            continue
        valid, reason = validate_materialization(root, require_utilities=False)
        if not valid:
            safe_copy = (
                _pre_materialization_command_is_safe(command, workdir or session_cwd)
            )
            safe_scaffold = _pre_materialization_scaffold_safe(command, workdir or session_cwd)
            if not safe_copy and not safe_scaffold and not _metadata_only_command(command):
                if re.search(r"(?:^|[\s;&|()])(?:cp|install)\b", command) and root.exists():
                    return (
                        "Blocked pre-materialization copy: target project root already exists. "
                        "Choose a fresh /home/shen/dev/<site-name> or stop; do not nest a template inside it."
                    )
                return (
                    "Blocked static-site terminal operation: existing project content cannot "
                    f"be read or generated before materialization ({reason}). Only project-directory "
                    "existence, empty project/docs scaffolding, local template copy, and nginx host "
                    "conflict checks are allowed."
                )
            if (not safe_copy and not safe_scaffold and
                    re.search(r"(?:/public(?:/|\b)|docs/(?:build_site|template_renderer|component_generator))", command)):
                return "Blocked: public/ and generator outputs require prior free-template materialization."
        if valid and not _post_materialization_copy_is_safe(command, workdir or session_cwd, root):
            return (
                "Blocked recursive copy into an authenticated static-site root: "
                "the materialized shell is immutable; use permitted content/image substitutions only."
            )
        receipt_mode = (_read_json(_receipt_path(root)) or {}).get('execution_mode')
        if valid and receipt_mode != FREE_EXECUTION_MODE and shell_write_command and any(
            re.search(rf"(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])", command)
            for name in REQUIRED_FILES
        ):
            return "Blocked static-site shell write: authenticated HTML/CSS/JS/template files must be changed through a shell-preserving write contract."
        if _FORBIDDEN_GENERATOR_RE.search(command):
            return "Blocked: materialized static-site publishing forbids build_site.py and renderer execution."
        if re.search(r"(?:/public(?:/|\b)|\bpublic/)", command) and re.search(r"\b(?:python|node|npm|yarn|vite|webpack|parcel)\b", command):
            return "Blocked: materialized static-site publishing cannot generate public/ with a renderer or build tool."
    return None

def validate_template_design(number: Any) -> tuple[bool, str]:
    """Reject catalog entries without a unique design-DNA identity."""
    selected = _package_for_number(number)
    if selected is None:
        return False, "selected package is unavailable"
    seen_layouts: set[str] = set()
    for sibling in sorted(p for p in SITES_ROOT.iterdir() if p.is_dir()):
        template = _read_json(sibling / "template.json") or {}
        layout_key = str(template.get("source_layout_key") or "")
        if not layout_key or layout_key in seen_layouts:
            return False, "template catalog contains a missing or duplicate source_layout_key"
        seen_layouts.add(layout_key)
        dna = template.get("design_dna")
        if not isinstance(dna, dict) or not str(dna.get("identity") or "").endswith("-source-specific-v3"):
            return False, f"design package {sibling.name} is missing source-specific-v3 design DNA"
        if dna.get("shared_base_shell") is not False:
            return False, f"design package {sibling.name} must declare shared_base_shell=false"
        trace = _read_json(sibling / "source-trace.json") or {}
        if trace.get("implementation_status") != "source-specific-shell-v3":
            return False, f"design package {sibling.name} is missing source-specific-shell-v3 trace status"
        visual = template.get("visual_contract")
        required_visual_keys = {
            "source_evidence_status", "source_layout_key", "visual_dimensions",
            "interaction_dimensions", "responsive_breakpoint", "observed_regions",
            "observed_interactions", "permitted_mutations", "source_implementation_copy",
        }
        if not isinstance(visual, dict) or not required_visual_keys <= set(visual):
            return False, f"design package {sibling.name} is missing its visual contract"
        if visual.get("source_implementation_copy") is not False:
            return False, f"design package {sibling.name} has an invalid source-copy contract"
        if visual.get("source_evidence_status") != trace.get("source_access"):
            return False, f"design package {sibling.name} has inconsistent source evidence status"
        if not visual.get("visual_dimensions") or not visual.get("interaction_dimensions"):
            return False, f"design package {sibling.name} has an incomplete visual contract"
        media_assets = visual.get("rendered_media_assets")
        if not isinstance(media_assets, list) or trace.get("rendered_media_assets") != media_assets:
            return False, f"design package {sibling.name} has an unaudited rendered-media asset list"
        for media in media_assets:
            if not isinstance(media, dict) or not isinstance(media.get("path"), str) or not isinstance(media.get("source_url"), str):
                return False, f"design package {sibling.name} has an invalid rendered-media record"
            asset_path = sibling / media["path"]
            if not asset_path.is_file() or media.get("sha256") != _sha256(asset_path):
                return False, f"design package {sibling.name} has a rendered-media hash mismatch"
        for shell_file in SHELL_FILES:
            if not (sibling / shell_file).is_file():
                return False, f"design package {sibling.name} is missing {shell_file}"
        slug = sibling.name[3:] if len(sibling.name) > 3 else sibling.name
        namespace = slug.replace("-", "_")
        index_text = (sibling / "index.html").read_text(encoding="utf-8", errors="ignore")
        css_text = (sibling / "styles.css").read_text(encoding="utf-8", errors="ignore")
        js_text = (sibling / "app.js").read_text(encoding="utf-8", errors="ignore")
        if 'data-stage-version="3"' not in index_text:
            return False, f"design package {sibling.name} is missing source-shaped v3 DOM"
        if f"source-shaped DOM v3: {slug}" not in css_text:
            return False, f"design package {sibling.name} is missing source-shaped v3 CSS"
        if f"source-shaped interaction v3: {slug}" not in js_text:
            return False, f"design package {sibling.name} is missing source-shaped v3 JS"
        for route in PUBLISHING_HTML_FILES:
            route_text = (sibling / route).read_text(encoding="utf-8", errors="ignore")
            route_name = route.removesuffix(".html")
            if f'data-route-version="4"' not in route_text or f'data-route-layout="{slug}-{route_name}"' not in route_text:
                return False, f"design package {sibling.name} is missing route contract for {route_name}"
        if f"source route contract v4: {slug}" not in css_text:
            return False, f"design package {sibling.name} is missing route CSS contract"
        if f"source route interaction contract v4: {slug}" not in js_text:
            return False, f"design package {sibling.name} is missing route JS contract"
    import difflib

    packages = sorted(p for p in SITES_ROOT.iterdir() if p.is_dir())

    def fingerprint(package: Path) -> tuple[list[str], list[str], list[str]]:
        html = re.findall(r"</?([a-z0-9]+)", (package / "index.html").read_text(encoding="utf-8", errors="ignore").lower())
        css = re.findall(r"([a-z-]+)[ ]*:", (package / "styles.css").read_text(encoding="utf-8", errors="ignore").lower())
        js = re.findall(r"(?:addEventListener|querySelector|classList|dataset|location|filter|toggle)", (package / "app.js").read_text(encoding="utf-8", errors="ignore").lower())
        return html, css, js

    fingerprints = {package: fingerprint(package) for package in packages}
    for index, package in enumerate(packages):
        for sibling in packages[index + 1:]:
            current_html, current_css, current_js = fingerprints[package]
            sibling_html, sibling_css, sibling_js = fingerprints[sibling]
            if (
                difflib.SequenceMatcher(None, current_html, sibling_html).ratio() >= 0.99
                and difflib.SequenceMatcher(None, current_css, sibling_css).ratio() >= 0.95
                and difflib.SequenceMatcher(None, current_js, sibling_js).ratio() >= 0.95
            ):
                return False, f"design collision between {package.name} and {sibling.name}: DOM/CSS/JS fingerprints are too similar"
    return True, "design DNA identity is present for all numbered packages"
