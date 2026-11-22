"""Vigil design tokens and Plotly layout helpers (air-gapped, light & dark)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    import plotly.graph_objects as go

VIGIL_LIGHT: Final[dict[str, str]] = {
    "bg": "#ffffff",
    "surface": "#f7f7f7",
    "text": "#1a1a1a",
    "muted": "#666666",
    "grid": "#e2e8f0",
    "rule": "#000000",
    "accent": "#057dbc",
    "tip": "#1a7f37",
    "warning": "#bf8700",
    "caution": "#bc4c00",
    "important": "#cf222e",
    "geo_land": "#f0f2f5",
    "geo_ocean": "#ffffff",
    "geo_border": "#cbd5e1",
}

VIGIL_DARK: Final[dict[str, str]] = {
    "bg": "#111111",
    "surface": "#1a1a1a",
    "text": "#e0e0e0",
    "muted": "#8c8c8c",
    "grid": "#2a2a2a",
    "rule": "#ffffff",
    "accent": "#4db8e0",
    "tip": "#6ab187",
    "warning": "#c9a84c",
    "caution": "#d4956a",
    "important": "#e07878",
    "geo_land": "#242424",
    "geo_ocean": "#111111",
    "geo_border": "#3d3d3d",
}

EVENT_TYPE_COLORS: Final[dict[str, str]] = {
    "Auth": "#057dbc",
    "Commands": "#bc4c00",
    "Findings": "#cf222e",
    "Network": "#1a7f37",
    "Downloads": "#6f42c1",
}

IOC_TYPE_COLORS: Final[dict[str, str]] = {
    "malware_hash": "#cf222e",
    "c2_ip": "#bc4c00",
    "stager_url": "#bf8700",
    "stager_domain": "#057dbc",
    "ssh_key": "#1a7f37",
}

FONT_STACK: Final[str] = (
    "Source Sans 3, system-ui, -apple-system, Segoe UI, Helvetica Neue, Arial, sans-serif"
)
MONO_STACK: Final[str] = "JetBrains Mono, ui-monospace, SF Mono, Consolas, Menlo, monospace"


def apply_vigil_layout(
    fig: go.Figure,
    *,
    height: int = 340,
    margin: dict[str, int] | None = None,
    extra: dict[str, object] | None = None,
) -> go.Figure:
    """Apply Vigil's sharp, paper-white baseline layout (client JS swaps dark tokens)."""
    layout: dict[str, object] = {
        "template": "none",
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font": {"family": FONT_STACK, "color": VIGIL_LIGHT["text"], "size": 12},
        "hoverlabel": {
            "bgcolor": VIGIL_LIGHT["surface"],
            "bordercolor": VIGIL_LIGHT["rule"],
            "font": {"family": MONO_STACK, "color": VIGIL_LIGHT["text"], "size": 12},
        },
        "height": height,
        "margin": margin or {"l": 45, "r": 20, "t": 18, "b": 42},
        "xaxis": {"gridcolor": VIGIL_LIGHT["grid"], "zerolinecolor": VIGIL_LIGHT["grid"]},
        "yaxis": {"gridcolor": VIGIL_LIGHT["grid"], "zerolinecolor": VIGIL_LIGHT["grid"]},
    }
    if extra:
        for key, value in extra.items():
            existing = layout.get(key)
            if isinstance(existing, dict) and isinstance(value, dict):
                layout[key] = {**existing, **value}
            else:
                layout[key] = value
    fig.update_layout(**layout)
    return fig
