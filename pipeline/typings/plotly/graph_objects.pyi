from collections.abc import Mapping, Sequence

class BaseTrace:
    name: str | None
    hovertemplate: str | None

class Bar(BaseTrace):
    def __init__(
        self,
        *,
        x: Sequence[str | float | int] = ...,
        y: Sequence[str | float | int | None] = ...,
        name: str | None = ...,
        orientation: str | None = ...,
        marker: Mapping[str, object] | None = ...,
        marker_color: str | Sequence[str] | None = ...,
        customdata: Sequence[object] | None = ...,
        hovertext: Sequence[str] | None = ...,
        hovertemplate: str | None = ...,
        text: Sequence[str] | None = ...,
        textposition: str | None = ...,
    ) -> None: ...

class Pie(BaseTrace):
    def __init__(
        self,
        *,
        labels: Sequence[str] = ...,
        values: Sequence[int | float] = ...,
        hole: float | None = ...,
        marker: Mapping[str, object] | None = ...,
        textinfo: str | None = ...,
        hovertemplate: str | None = ...,
        sort: bool | None = ...,
    ) -> None: ...

class Scatter(BaseTrace):
    def __init__(
        self,
        *,
        x: Sequence[object] = ...,
        y: Sequence[object] = ...,
        mode: str | None = ...,
        name: str | None = ...,
        yaxis: str | None = ...,
        marker: Mapping[str, object] | None = ...,
        line: Mapping[str, object] | None = ...,
        customdata: Sequence[object] | None = ...,
        text: Sequence[str] | None = ...,
        hovertext: Sequence[str] | None = ...,
        hovertemplate: str | None = ...,
        hoverinfo: str | None = ...,
        showlegend: bool | None = ...,
        meta: object = ...,
        fill: str | None = ...,
        fillcolor: str | None = ...,
    ) -> None: ...

class Scattergeo(BaseTrace):
    def __init__(
        self,
        *,
        lat: Sequence[float] = ...,
        lon: Sequence[float] = ...,
        name: str | None = ...,
        mode: str | None = ...,
        text: Sequence[str] | None = ...,
        hovertemplate: str | None = ...,
        marker: Mapping[str, object] | None = ...,
    ) -> None: ...

class Histogram(BaseTrace):
    def __init__(
        self,
        *,
        x: Sequence[float | int] = ...,
        name: str | None = ...,
        xbins: Mapping[str, object] | None = ...,
        nbinsx: int | None = ...,
        marker: Mapping[str, object] | None = ...,
        marker_color: str | None = ...,
        hovertemplate: str | None = ...,
    ) -> None: ...

class Figure:
    data: tuple[BaseTrace, ...]
    def __init__(self, data: BaseTrace | Sequence[BaseTrace] | None = ...) -> None: ...
    def add_trace(self, trace: BaseTrace) -> Figure: ...
    def add_bar(
        self,
        *,
        x: Sequence[str | float | int] = ...,
        y: Sequence[str | float | int | None] = ...,
        name: str | None = ...,
        orientation: str | None = ...,
        marker: Mapping[str, object] | None = ...,
        marker_color: str | Sequence[str] | None = ...,
        customdata: Sequence[object] | None = ...,
        hovertemplate: str | None = ...,
    ) -> Figure: ...
    def add_scatter(
        self,
        *,
        x: Sequence[object] = ...,
        y: Sequence[object] = ...,
        name: str | None = ...,
        yaxis: str | None = ...,
        mode: str | None = ...,
        line: Mapping[str, object] | None = ...,
        marker: Mapping[str, object] | None = ...,
        hovertemplate: str | None = ...,
    ) -> Figure: ...
    def add_hline(
        self,
        *,
        y: float | int,
        line_dash: str | None = ...,
        line_color: str | None = ...,
        yref: str | None = ...,
        annotation_text: str | None = ...,
        annotation_position: str | None = ...,
    ) -> Figure: ...
    def update_layout(self, **kwargs: object) -> Figure: ...
    def update_geos(self, **kwargs: object) -> Figure: ...
    def update_traces(self, **kwargs: object) -> Figure: ...
    def to_dict(self) -> dict[str, object]: ...
