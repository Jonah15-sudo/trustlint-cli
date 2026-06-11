from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

import networkx as nx
import numpy as np
import plotly.graph_objects as go
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse


@dataclass(slots=True)
class DashboardSnapshot:
    graph: Dict[str, Any]
    title: str = "SPL v7 Topology Dashboard"


class TopologySurfaceBuilder:
    def __init__(self, grid_size: int = 40, sigma: float = 0.65) -> None:
        self.grid_size = int(grid_size)
        self.sigma = float(sigma)

    def build(self, snapshot: Mapping[str, Any]) -> Dict[str, Any]:
        graph = nx.DiGraph()
        for node in snapshot.get("nodes", []):
            graph.add_node(node["id"], **node)
        for edge in snapshot.get("edges", []):
            graph.add_edge(edge["source"], edge["target"], **edge)

        positions = self._layout(graph)
        xs = np.linspace(-1.2, 1.2, self.grid_size)
        ys = np.linspace(-1.2, 1.2, self.grid_size)
        z = np.zeros((self.grid_size, self.grid_size), dtype=float)

        feature_edges = snapshot.get("edges", [])
        for edge in feature_edges:
            source = edge["source"]
            target = edge["target"]
            src_pos = positions.get(source, np.array([0.0, 0.0]))
            tgt_pos = positions.get(target, np.array([0.0, 0.0]))
            weight = float(edge.get("weight", 0.0))
            confidence = float(edge.get("confidence", 1.0))
            independence = float(edge.get("independence", 1.0))
            stability = float(edge.get("weighted_stability", 1.0))
            corroboration = float(edge.get("cross_source_corroboration", 1.0))
            intervention = float(edge.get("intervention_effect", 0.0))
            intervention_gate = 0.5 + min(0.5, abs(intervention))
            effective_weight = weight * confidence * independence * stability * corroboration * intervention_gate
            self._add_gaussian_ridge(z, xs, ys, src_pos, effective_weight * 0.45)
            self._add_gaussian_ridge(z, xs, ys, tgt_pos, effective_weight * 0.20)

        return {
            "graph": graph,
            "positions": positions,
            "x": xs,
            "y": ys,
            "z": z,
        }

    def _layout(self, graph: nx.DiGraph) -> Dict[str, np.ndarray]:
        if graph.number_of_nodes() == 0:
            return {}
        try:
            pos = nx.spring_layout(graph, seed=42, dim=2, k=0.9)
        except Exception:
            pos = nx.circular_layout(graph, dim=2)
        return {k: np.array(v, dtype=float) for k, v in pos.items()}

    def _add_gaussian_ridge(self, z: np.ndarray, xs: np.ndarray, ys: np.ndarray, center: np.ndarray, amplitude: float) -> None:
        cx, cy = float(center[0]), float(center[1])
        for iy, y in enumerate(ys):
            for ix, x in enumerate(xs):
                dist2 = (x - cx) ** 2 + (y - cy) ** 2
                z[iy, ix] += amplitude * float(np.exp(-dist2 / (2.0 * self.sigma ** 2)))


def build_dashboard_html(snapshot: Mapping[str, Any], title: str = "SPL v7 Topology Dashboard") -> str:
    builder = TopologySurfaceBuilder()
    surface = builder.build(snapshot)
    graph: nx.DiGraph = surface["graph"]
    positions = surface["positions"]
    x = surface["x"]
    y = surface["y"]
    z = surface["z"]

    feature_names = [node["id"] for node in snapshot.get("nodes", []) if node.get("type") == "feature"]
    edge_map = {(e["source"], e["target"]): float(e.get("weight", 0.0)) for e in snapshot.get("edges", [])}

    surface_fig = go.Figure(
        data=[
            go.Surface(x=x, y=y, z=z, colorscale="Viridis", showscale=True, opacity=0.95)
        ]
    )
    surface_fig.update_layout(
        title="Topology Surface",
        scene=dict(
            xaxis_title="Topology X",
            yaxis_title="Topology Y",
            zaxis_title="Risk / Tension",
            aspectmode="cube",
        ),
        margin=dict(l=0, r=0, t=40, b=0),
    )

    node_x = []
    node_y = []
    node_text = []
    node_color = []
    for node in graph.nodes():
        pos = positions.get(node, np.array([0.0, 0.0]))
        node_x.append(float(pos[0]))
        node_y.append(float(pos[1]))
        node_text.append(node)
        node_color.append(0.2 if node == snapshot.get("target") else 0.6)

    edge_x = []
    edge_y = []
    for source, target in graph.edges():
        sx, sy = positions.get(source, np.array([0.0, 0.0]))
        tx, ty = positions.get(target, np.array([0.0, 0.0]))
        edge_x.extend([float(sx), float(tx), None])
        edge_y.extend([float(sy), float(ty), None])

    network_fig = go.Figure()
    network_fig.add_trace(
        go.Scatter(
            x=edge_x,
            y=edge_y,
            mode="lines",
            line=dict(width=1, color="#9aa0a6"),
            hoverinfo="none",
        )
    )
    network_fig.add_trace(
        go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers+text",
            text=node_text,
            textposition="top center",
            marker=dict(size=16, color=node_color, colorscale="Blues", line=dict(width=1, color="#111")),
            hovertemplate="%{text}<extra></extra>",
        )
    )
    network_fig.update_layout(
        title="Learned Causal Topology",
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        margin=dict(l=0, r=0, t=40, b=0),
    )

    heatmap_data = np.zeros((len(feature_names), len(feature_names)), dtype=float)
    for i, src in enumerate(feature_names):
        for j, tgt in enumerate(feature_names):
            if src == tgt:
                heatmap_data[i, j] = 0.0
            else:
                heatmap_data[i, j] = edge_map.get((src, snapshot.get("target")), 0.0) - edge_map.get((tgt, snapshot.get("target")), 0.0)

    heatmap_fig = go.Figure(
        data=[
            go.Heatmap(
                z=heatmap_data if feature_names else [[0.0]],
                x=feature_names if feature_names else ["n/a"],
                y=feature_names if feature_names else ["n/a"],
                colorscale="RdBu",
                zmid=0.0,
                colorbar=dict(title="Δ Weight"),
            )
        ]
    )
    heatmap_fig.update_layout(
        title="Feature Influence Matrix",
        margin=dict(l=0, r=0, t=40, b=0),
    )

    summary_html = f"""
    <div style="font-family: Arial, sans-serif; padding: 16px;">
      <h1 style="margin: 0 0 8px 0;">{title}</h1>
      <p style="margin: 0 0 12px 0;">
        Samples: <b>{snapshot.get('samples_seen', 0)}</b> |
        Accuracy: <b>{snapshot.get('accuracy', 0.0):.3f}</b> |
        Avg loss: <b>{snapshot.get('avg_loss', 0.0):.4f}</b> |
        Weighted acc: <b>{snapshot.get('weighted_accuracy', 0.0):.3f}</b> |
        Bus: <b>{snapshot.get('bus', 'memory')}</b>
      </p>
      <p style="margin: 0 0 12px 0; color:#444;">
        Constraints: stability v2 / independence v2 / cross-source corroboration / source verification / intervention approximation are applied to edge confidence and the topology surface.
      </p>
    </div>
    """

    return "\n".join(
        [
            "<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>",
            f"<title>{title}</title>",
            "<script src='https://cdn.plot.ly/plotly-2.35.2.min.js'></script>",
            "<style>body{margin:0;background:#fafafa;} .grid{display:grid;grid-template-columns:1fr;gap:18px;padding:16px;} .card{background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,0.08);padding:12px;}</style>",
            "</head><body>",
            summary_html,
            "<div class='grid'>",
            f"<div class='card'>{surface_fig.to_html(full_html=False, include_plotlyjs=False)}</div>",
            f"<div class='card'>{network_fig.to_html(full_html=False, include_plotlyjs=False)}</div>",
            f"<div class='card'>{heatmap_fig.to_html(full_html=False, include_plotlyjs=False)}</div>",
            "</div>",
            "</body></html>",
        ]
    )


def create_app(state_provider: Optional[Callable[[], Mapping[str, Any]]] = None) -> FastAPI:
    app = FastAPI(title="SPL v7 Dashboard")

    def _state() -> Mapping[str, Any]:
        if state_provider is None:
            return {
                "graph": {
                    "nodes": [],
                    "edges": [],
                    "target": "decision",
                    "samples_seen": 0,
                    "accuracy": 0.0,
                    "avg_loss": 0.0,
                    "bus": "memory",
                }
            }
        return state_provider()

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        state = _state()
        graph = state.get("graph", state)
        return HTMLResponse(build_dashboard_html(graph, title="SPL v7 Topology Dashboard"))

    @app.get("/api/snapshot")
    async def snapshot() -> JSONResponse:
        state = _state()
        return JSONResponse(content=dict(state))

    @app.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
