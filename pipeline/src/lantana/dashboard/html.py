"""Self-contained Vigil HTML/JS renderer for the Lantana Intelligence Console.

Air-gapped by construction:
- References ONLY local ``/static/vigil.css`` and ``/static/plotly.min.js``.
- Zero external CDNs, font hosts, or remote URLs.
- All user/data text is HTML-escaped via ``html.escape`` and inline JSON
  escapes ``</`` to ``<\\/`` to prevent script breakout.
"""

from __future__ import annotations

import html as html_lib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import plotly.io as pio

from lantana.dashboard.theme import VIGIL_DARK, VIGIL_LIGHT
from lantana.notify.explanations import BRIEF_SECTIONS, METRICS

if TYPE_CHECKING:
    from collections.abc import Sequence

    import plotly.graph_objects as go

    from lantana.dashboard.queries import DateWindow

NAV_ROUTES: tuple[tuple[str, str], ...] = (
    ("/overview", "Overview"),
    ("/iocs", "Malware & IOCs"),
    ("/ips", "IP Reputation"),
    ("/geography", "Geography"),
    ("/credentials", "Credentials"),
    ("/progression", "Progression"),
    ("/findings", "Findings"),
    ("/stix", "STIX & Export"),
    ("/health", "Health"),
)


@dataclass(frozen=True)
class KpiCard:
    label: str
    value: str
    sub: str = ""
    tone: str = ""  # "", "high", "med", "low", "info"
    metric_key: str | None = None


@dataclass(frozen=True)
class TableColumn:
    key: str
    label: str
    numeric: bool = False
    mono: bool = False
    badge: bool = False


def esc(value: object) -> str:
    """HTML-escape any value cleanly."""
    if value is None:
        return "—"
    text = str(value)
    return html_lib.escape(text, quote=True) if text else "—"


def safe_json_for_script(payload: object) -> str:
    """Serialize JSON safely for embedding inside an HTML ``<script>`` tag.

    Escapes ``<``, ``>``, ``&``, and line separators so attacker-controlled
    strings (such as ``<!--<script>`` or ``</script>``) can never trigger HTML5
    script-data double-escaped parser confusion or break out of the block.
    """
    raw = json.dumps(payload, separators=(",", ":"))
    return _escape_json_for_script(raw)


def _escape_json_for_script(raw_json: str) -> str:
    return (
        raw_json.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def window_query_string(window: DateWindow) -> str:
    """Build URL query string preserving the active global window across nav links."""
    params: dict[str, str] = {"window": window.mode}
    if window.mode == "custom" and window.start_date and window.end_date:
        params["start"] = window.start_date.isoformat()
        params["end"] = window.end_date.isoformat()
    return urlencode(params)


def render_help_tip(text: str | None, *, css_class: str = "") -> str:
    """Render a collapsible ``<details>`` What/Why/How explanation block."""
    if not text:
        return ""
    cls = f"help-tip {css_class}".strip()
    return (
        f'<details class="{cls}">'
        "<summary>What / Why / How</summary>"
        f'<div class="help-body">{esc(text)}</div>'
        "</details>"
    )


def metric_help_text(key: str | None) -> str | None:
    if not key:
        return None
    triplet = METRICS.get(key)
    return triplet.tooltip() if triplet is not None else None


def section_help_text(key: str | None) -> str | None:
    if not key:
        return None
    triplet = BRIEF_SECTIONS.get(key)
    return triplet.tooltip() if triplet is not None else None


def render_kpis(cards: Sequence[KpiCard]) -> str:
    parts: list[str] = ['<div class="kpi-grid">']
    for card in cards:
        tone_cls = f" tone-{card.tone}" if card.tone else ""
        help_html = render_help_tip(metric_help_text(card.metric_key))
        sub_html = f'<div class="kpi-sub">{esc(card.sub)}</div>' if card.sub else ""
        parts.append(
            f'<div class="kpi-card{tone_cls}">'
            f'<div class="kpi-label">{esc(card.label)}</div>'
            f'<div class="kpi-value">{esc(card.value)}</div>'
            f"{sub_html}"
            f"{help_html}"
            "</div>"
        )
    parts.append("</div>")
    return "".join(parts)


def render_section_heading(anchor: str, title: str, *, help_key: str | None = None) -> str:
    help_html = render_help_tip(section_help_text(help_key), css_class="section-help")
    return f'<h2 id="{esc(anchor)}">{esc(title)}</h2>{help_html}'


def render_chart_card(
    chart_id: str,
    title: str,
    fig: go.Figure,
    *,
    help_key: str | None = None,
) -> str:
    """Render a Vigil chart card whose Plotly JSON hydrates client-side."""
    fig_json = _escape_json_for_script(pio.to_json(fig))
    help_html = render_help_tip(section_help_text(help_key))
    return (
        '<div class="chart-card">'
        f'<div class="chart-card-title">{esc(title)}</div>'
        f"{help_html}"
        f'<div id="{esc(chart_id)}" class="plotly-host" data-plotly-chart="1"></div>'
        f'<script type="application/json" data-for="{esc(chart_id)}">{fig_json}</script>'
        "</div>"
    )


def render_interactive_table(
    table_id: str,
    columns: Sequence[TableColumn],
    rows: Sequence[dict[str, object]],
    *,
    page_size: int = 25,
    search_placeholder: str = "Filter rows...",
    min_risk_filter: bool = False,
    min_stage_filter: bool = False,
    ioc_type_filter: bool = False,
    empty_message: str = "No records for this window.",
) -> str:
    """Render a client-side searchable, sortable, paginated table from JSON payload."""
    if not rows:
        return f'<div class="callout">{esc(empty_message)}</div>'

    col_meta = [
        {
            "key": c.key,
            "label": c.label,
            "numeric": c.numeric,
            "mono": c.mono,
            "badge": c.badge,
        }
        for c in columns
    ]
    filter_controls: list[str] = [
        f'<input type="search" class="ctrl-input tbl-search" '
        f'placeholder="{esc(search_placeholder)}" aria-label="Filter table">'
    ]
    if min_risk_filter:
        filter_controls.append(
            '<label class="window-label">Min risk '
            '<input type="number" class="ctrl-input tbl-min-risk" '
            'min="0" max="100" step="5" value="0" style="width:4.5rem">'
            "</label>"
        )
    if min_stage_filter:
        filter_controls.append(
            '<label class="window-label">Min stage '
            '<select class="ctrl-select tbl-min-stage">'
            '<option value="1">1 — Scan</option>'
            '<option value="2">2 — Credential</option>'
            '<option value="3">3 — Authenticated</option>'
            '<option value="4">4 — Interactive</option>'
            "</select></label>"
        )
    if ioc_type_filter:
        filter_controls.append(
            '<label class="window-label">IOC type '
            '<select class="ctrl-select tbl-ioc-type">'
            '<option value="">All types</option>'
            '<option value="malware_hash">Malware Hash</option>'
            '<option value="c2_ip">Outbound C2 IP</option>'
            '<option value="stager_url">Stager URL</option>'
            '<option value="stager_domain">Stager Domain</option>'
            '<option value="ssh_key">SSH Public Key</option>'
            "</select></label>"
        )

    payload = {
        "columns": col_meta,
        "rows": list(rows),
        "pageSize": page_size,
    }
    head_cells = "".join(
        f'<th data-col="{esc(c.key)}" data-num="{"1" if c.numeric else "0"}">{esc(c.label)}</th>'
        for c in columns
    )
    return (
        f'<div class="tbl-widget" id="{esc(table_id)}" data-table-widget="1">'
        '<div class="table-toolbar">'
        f'<div class="table-filters">{"".join(filter_controls)}</div>'
        '<div class="table-meta tbl-status"></div>'
        "</div>"
        '<div class="table-wrap">'
        '<table class="data-table">'
        f"<thead><tr>{head_cells}</tr></thead>"
        "<tbody></tbody>"
        "</table>"
        "</div>"
        '<div class="pager">'
        '<button type="button" class="tbl-prev">Prev</button>'
        '<span class="table-meta tbl-page"></span>'
        '<button type="button" class="tbl-next">Next</button>'
        "</div>"
        f'<script type="application/json" data-table-data="{esc(table_id)}">'
        f"{safe_json_for_script(payload)}"
        "</script>"
        "</div>"
    )


def render_badge(value: object) -> str:
    """Render a Vigil semantic status badge matching client-side ``badgeHtml``."""
    text = "" if value is None else str(value).strip()
    if not text:
        return "—"
    low = text.lower()
    if low in {
        "high",
        "malicious",
        "malware_hash",
        "critical",
        "error",
        "failed",
        "silent (2+d)",
    }:
        cls = "badge badge-high"
    elif low in {
        "medium",
        "suspicious",
        "c2_ip",
        "stager_url",
        "warning",
        "warning (rate limit)",
        "degraded",
        "silent (1d)",
        "cooldown",
    }:
        cls = "badge badge-med"
    elif low in {
        "low",
        "benign",
        "ssh_key",
        "ok",
        "healthy",
        "active",
        "success",
        "configured",
        "configured (gti)",
        "configured (free)",
        "configured (keyed)",
    }:
        cls = "badge badge-low"
    else:
        cls = "badge badge-info"
    return f'<span class="{cls}">{esc(text)}</span>'


def render_simple_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[object]],
    *,
    numeric_cols: set[int] | None = None,
    mono_cols: set[int] | None = None,
    badge_cols: set[int] | None = None,
    empty_message: str = "No records for this window.",
) -> str:
    """Render a compact static table (e.g. top-10 lists on Overview/Credentials/Health)."""
    if not rows:
        return f'<div class="callout">{esc(empty_message)}</div>'
    num_set = numeric_cols or set()
    mono_set = mono_cols or set()
    badge_set = badge_cols or set()
    thead = "".join(f"<th>{esc(h)}</th>" for h in headers)
    tbody_rows: list[str] = []
    for row in rows:
        tds: list[str] = []
        for idx, cell in enumerate(row):
            cls_parts: list[str] = []
            if idx in num_set:
                cls_parts.append("num")
            if idx in mono_set:
                cls_parts.append("mono")
            cls_attr = f' class="{" ".join(cls_parts)}"' if cls_parts else ""
            content = render_badge(cell) if idx in badge_set else esc(cell)
            tds.append(f"<td{cls_attr}>{content}</td>")
        tbody_rows.append(f"<tr>{''.join(tds)}</tr>")
    return (
        '<div class="table-wrap">'
        f'<table class="data-table"><thead><tr>{thead}</tr></thead>'
        f"<tbody>{''.join(tbody_rows)}</tbody></table>"
        "</div>"
    )


_CONSOLE_JS = """
(function() {
  var LIGHT = __VIGIL_LIGHT__;
  var DARK = __VIGIL_DARK__;

  function getTheme() {
    return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
  }

  function applyTheme(theme) {
    if (theme === "dark") {
      document.documentElement.setAttribute("data-theme", "dark");
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
    var btn = document.getElementById("theme-toggle-btn");
    if (btn) btn.textContent = theme === "dark" ? "Light" : "Dark";
    try { localStorage.setItem("vigil-theme", theme); } catch (e) {}
    restyleCharts(theme);
  }

  function chartRelayoutPayload(theme) {
    var p = theme === "dark" ? DARK : LIGHT;
    return {
      "font.color": p.text,
      "xaxis.gridcolor": p.grid,
      "xaxis.zerolinecolor": p.grid,
      "yaxis.gridcolor": p.grid,
      "yaxis.zerolinecolor": p.grid,
      "hoverlabel.bgcolor": p.surface,
      "hoverlabel.bordercolor": p.rule,
      "hoverlabel.font.color": p.text
    };
  }

  function restyleSingleChart(el, theme) {
    if (!el.data) return;
    var p = theme === "dark" ? DARK : LIGHT;
    var update = chartRelayoutPayload(theme);
    if (el.layout && el.layout.meta === "world-map") {
      update["plot_bgcolor"] = p.geo_ocean;
    }
    try { Plotly.relayout(el, update); } catch (e) {}
    var landIndices = [];
    for (var i = 0; i < el.data.length; i++) {
      if (el.data[i] && el.data[i].meta === "world-land") {
        landIndices.push(i);
      }
    }
    if (landIndices.length > 0) {
      try {
        Plotly.restyle(el, {
          fillcolor: p.geo_land,
          "line.color": p.geo_border
        }, landIndices);
      } catch (e) {}
    }
  }

  function restyleCharts(theme) {
    if (typeof Plotly === "undefined") return;
    document.querySelectorAll('[data-plotly-chart="1"]').forEach(function(el) {
      restyleSingleChart(el, theme);
    });
  }

  function initCharts() {
    if (typeof Plotly === "undefined") return;
    var theme = getTheme();
    document.querySelectorAll('[data-plotly-chart="1"]').forEach(function(el) {
      var script = document.querySelector('script[data-for="' + el.id + '"]');
      if (!script) return;
      try {
        var spec = JSON.parse(script.textContent);
        Plotly.newPlot(el, spec.data || [], spec.layout || {}, {
          responsive: true,
          displaylogo: false,
          modeBarButtonsToRemove: ["lasso2d", "select2d"]
        }).then(function() {
          if (theme === "dark") {
            restyleSingleChart(el, theme);
          }
        });
      } catch (e) {
        el.textContent = "Chart render error";
      }
    });
  }

  function escapeHtml(v) {
    if (v === null || v === undefined || v === "") return "—";
    return String(v)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function badgeHtml(val) {
    var s = String(val || "");
    var low = s.toLowerCase();
    var cls = "badge";
    if (
      low === "high" || low === "malicious" || low === "malware_hash" ||
      low === "critical" || low === "error" || low === "failed"
    ) {
      cls += " badge-high";
    } else if (
      low === "medium" || low === "suspicious" ||
      low === "c2_ip" || low === "stager_url" ||
      low === "warning" || low === "warning (rate limit)" || low === "degraded"
    ) {
      cls += " badge-med";
    } else if (
      low === "low" || low === "benign" || low === "ssh_key" ||
      low === "ok" || low === "healthy" || low === "active" || low === "success"
    ) {
      cls += " badge-low";
    } else {
      cls += " badge-info";
    }
    return '<span class="' + cls + '">' + escapeHtml(s) + "</span>";
  }

  function initTableWidget(widget) {
    var script = widget.querySelector('script[data-table-data="' + widget.id + '"]');
    if (!script) return;
    var cfg = JSON.parse(script.textContent);
    var columns = cfg.columns || [];
    var allRows = cfg.rows || [];
    var pageSize = cfg.pageSize || 25;
    var state = { page: 1, sortKey: null, sortAsc: false };

    var tbody = widget.querySelector("tbody");
    var statusEl = widget.querySelector(".tbl-status");
    var pageEl = widget.querySelector(".tbl-page");
    var prevBtn = widget.querySelector(".tbl-prev");
    var nextBtn = widget.querySelector(".tbl-next");
    var searchInput = widget.querySelector(".tbl-search");
    var minRiskInput = widget.querySelector(".tbl-min-risk");
    var minStageSelect = widget.querySelector(".tbl-min-stage");
    var iocTypeSelect = widget.querySelector(".tbl-ioc-type");

    function filteredRows() {
      var q = searchInput ? searchInput.value.trim().toLowerCase() : "";
      var minRisk = minRiskInput ? parseFloat(minRiskInput.value || "0") : 0;
      var minStage = minStageSelect ? parseInt(minStageSelect.value || "1", 10) : 1;
      var iocType = iocTypeSelect ? iocTypeSelect.value : "";

      var out = allRows.filter(function(r) {
        if (minRisk > 0 && Number(r.risk_score || 0) < minRisk) return false;
        if (minStage > 1 && Number(r.max_stage || 0) < minStage) return false;
        if (iocType && String(r.ioc_type || "") !== iocType) return false;
        if (!q) return true;
        for (var i = 0; i < columns.length; i++) {
          var val = r[columns[i].key];
          if (val !== null && val !== undefined && String(val).toLowerCase().indexOf(q) !== -1) {
            return true;
          }
        }
        return false;
      });

      if (state.sortKey) {
        var col = columns.find(function(c) { return c.key === state.sortKey; });
        var isNum = col && col.numeric;
        var mult = state.sortAsc ? 1 : -1;
        out = out.slice().sort(function(a, b) {
          var av = a[state.sortKey];
          var bv = b[state.sortKey];
          if (av === null || av === undefined || av === "") return 1;
          if (bv === null || bv === undefined || bv === "") return -1;
          if (isNum) return (Number(av) - Number(bv)) * mult;
          return String(av).localeCompare(String(bv)) * mult;
        });
      }
      return out;
    }

    function render() {
      var rows = filteredRows();
      var totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
      if (state.page > totalPages) state.page = totalPages;
      var start = (state.page - 1) * pageSize;
      var slice = rows.slice(start, start + pageSize);

      tbody.innerHTML = slice.map(function(r) {
        return "<tr>" + columns.map(function(c) {
          var cls = [];
          if (c.numeric) cls.push("num");
          if (c.mono) cls.push("mono");
          var v = r[c.key];
          var content = c.badge && v ? badgeHtml(v) : escapeHtml(v);
          var attr = cls.length ? ' class="' + cls.join(" ") + '"' : "";
          return "<td" + attr + ">" + content + "</td>";
        }).join("") + "</tr>";
      }).join("");

      if (statusEl) {
        statusEl.textContent =
          rows.length.toLocaleString() + " of " + allRows.length.toLocaleString() + " rows";
      }
      if (pageEl) {
        pageEl.textContent = "Page " + state.page + " / " + totalPages;
      }
      if (prevBtn) prevBtn.disabled = state.page <= 1;
      if (nextBtn) nextBtn.disabled = state.page >= totalPages;
    }

    widget.querySelectorAll("thead th").forEach(function(th) {
      th.addEventListener("click", function() {
        var key = th.getAttribute("data-col");
        if (state.sortKey === key) {
          state.sortAsc = !state.sortAsc;
        } else {
          state.sortKey = key;
          state.sortAsc = th.getAttribute("data-num") !== "1";
        }
        widget.querySelectorAll("thead th").forEach(function(h) {
          h.classList.remove("sort-asc", "sort-desc");
        });
        th.classList.add(state.sortAsc ? "sort-asc" : "sort-desc");
        state.page = 1;
        render();
      });
    });

    function resetAndRender() { state.page = 1; render(); }
    if (searchInput) searchInput.addEventListener("input", resetAndRender);
    if (minRiskInput) minRiskInput.addEventListener("input", resetAndRender);
    if (minStageSelect) minStageSelect.addEventListener("change", resetAndRender);
    if (iocTypeSelect) iocTypeSelect.addEventListener("change", resetAndRender);
    if (prevBtn) {
      prevBtn.addEventListener("click", function() {
        if (state.page > 1) { state.page--; render(); }
      });
    }
    if (nextBtn) {
      nextBtn.addEventListener("click", function() { state.page++; render(); });
    }

    render();
  }

  function initWindowForm() {
    var sel = document.getElementById("window-select");
    var customBox = document.getElementById("custom-range-box");
    var form = document.getElementById("window-form");
    if (!sel || !form) return;
    sel.addEventListener("change", function() {
      if (sel.value === "custom") {
        if (customBox) customBox.classList.remove("hidden");
      } else {
        if (customBox) customBox.classList.add("hidden");
        form.submit();
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function() {
    var toggle = document.getElementById("theme-toggle-btn");
    if (toggle) {
      toggle.textContent = getTheme() === "dark" ? "Light" : "Dark";
      toggle.addEventListener("click", function() {
        applyTheme(getTheme() === "dark" ? "light" : "dark");
      });
    }
    initWindowForm();
    document.querySelectorAll('[data-table-widget="1"]').forEach(initTableWidget);
    if (typeof Plotly !== "undefined") {
      initCharts();
    } else {
      window.addEventListener("load", initCharts);
    }
  });
})();
"""


def render_page(
    *,
    title: str,
    subtitle: str,
    active_route: str,
    window: DateWindow,
    toc_items: Sequence[tuple[str, str]],
    body_html: str,
    operation_name: str = "Lantana",
) -> str:
    """Wrap page content in the complete self-contained Vigil HTML5 document."""
    qs = window_query_string(window)
    nav_links: list[str] = []
    for path, label in NAV_ROUTES:
        active_cls = " active" if path == active_route else ""
        nav_links.append(f'<a class="nav-link{active_cls}" href="{path}?{qs}">{esc(label)}</a>')

    mode_options = (
        ("latest", "Latest"),
        ("7d", "Last 7d"),
        ("30d", "Last 30d"),
        ("custom", "Custom Range"),
        ("all", "All-Time"),
    )
    opts_html = "".join(
        f'<option value="{val}"{" selected" if window.mode == val else ""}>{lbl}</option>'
        for val, lbl in mode_options
    )
    start_val = window.start_date.isoformat() if window.start_date else ""
    end_val = window.end_date.isoformat() if window.end_date else ""
    custom_cls = "" if window.mode == "custom" else " hidden"

    toc_html = ""
    if toc_items:
        links = "".join(f'<li><a href="#{esc(aid)}">{esc(lbl)}</a></li>' for aid, lbl in toc_items)
        toc_html = (
            '<aside class="sidebar toc-left">'
            '<div class="toc-title">On this view</div>'
            f'<ul class="toc-list">{links}</ul>'
            "</aside>"
        )

    inline_js = _CONSOLE_JS.replace("__VIGIL_LIGHT__", safe_json_for_script(VIGIL_LIGHT)).replace(
        "__VIGIL_DARK__", safe_json_for_script(VIGIL_DARK)
    )

    return (
        "<!DOCTYPE html>"
        '<html lang="en">'
        "<head>"
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{esc(title)} — {esc(operation_name)} Intel Console</title>"
        "<script>"
        "(function(){try{if(localStorage.getItem('vigil-theme')==='dark'){"
        "document.documentElement.setAttribute('data-theme','dark');}}catch(e){}})();"
        "</script>"
        '<link rel="stylesheet" href="/static/vigil.css">'
        '<script src="/static/plotly.min.js" defer></script>'
        "</head>"
        "<body>"
        '<header class="navbar">'
        '<div class="navbar-inner">'
        '<div class="navbar-left">'
        f'<a class="navbar-brand" href="/overview?{qs}">Lantana '
        '<span class="brand-tag">Intel Console</span></a>'
        f'<nav class="navbar-nav" aria-label="Primary">{"".join(nav_links)}</nav>'
        "</div>"
        '<div class="navbar-right">'
        f'<form id="window-form" class="window-form" method="get" action="{esc(active_route)}">'
        '<label class="window-label" for="window-select">Window</label>'
        f'<select id="window-select" name="window" class="ctrl-select">{opts_html}</select>'
        f'<span id="custom-range-box" class="custom-range-fields{custom_cls}">'
        f'<input type="date" name="start" class="ctrl-input" value="{esc(start_val)}" '
        'aria-label="Start date">'
        '<span class="window-label">→</span>'
        f'<input type="date" name="end" class="ctrl-input" value="{esc(end_val)}" '
        'aria-label="End date">'
        '<button type="submit" class="btn">Apply</button>'
        "</span>"
        "</form>"
        '<button type="button" id="theme-toggle-btn" class="theme-toggle" '
        'aria-label="Toggle dark mode">Dark</button>'
        "</div>"
        "</div>"
        "</header>"
        '<main class="main-container">'
        f'<div class="console-layout">{toc_html}'
        '<div class="console-main">'
        '<div class="page-header">'
        f'<div class="page-eyebrow">{esc(operation_name)} · {esc(window.label)}</div>'
        f"<h1>{esc(title)}</h1>"
        f'<p class="page-subtitle">{esc(subtitle)}</p>'
        "</div>"
        f"{body_html}"
        "</div>"
        "</div>"
        "</main>"
        '<footer class="nav-footer">'
        "Lantana v1.5 · Self-contained air-gapped Vigil Console · Bound to 127.0.0.1"
        "</footer>"
        f"<script>{inline_js}</script>"
        "</body>"
        "</html>"
    )
