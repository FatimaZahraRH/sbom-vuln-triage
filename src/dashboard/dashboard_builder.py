"""Dashboard HTML statique (Plotly), auto-suffisant -- tableau de bord de
pilotage de conformité, dans l'esprit d'un dashboard NETVIBES."""
from __future__ import annotations

from src.evaluation.metrics import TriageComparison
from src.triage.models import TriageResult


def build_dashboard_html(
    results: list[TriageResult],
    comparison: TriageComparison,
    output_path: str,
) -> None:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    from src.triage.engine import rank_by_cvss_only, rank_by_multi_factor

    fig = make_subplots(
        rows=2, cols=2,
        specs=[[{"type": "bar"}, {"type": "bar"}], [{"type": "scatter"}, {"type": "bar"}]],
        subplot_titles=(
            "Top 5 -- Classement CVSS seul",
            "Top 5 -- Classement multi-facteurs (CVSS+EPSS+KEV)",
            "CVSS vs EPSS par CVE (taille = score multi-facteurs)",
            f"Couverture KEV dans le top-{comparison.top_n}",
        ),
        vertical_spacing=0.18,
    )

    cvss_ranked = rank_by_cvss_only(results)[:5]
    multi_ranked = rank_by_multi_factor(results)[:5]

    def colors_for(items):
        return ["#B00020" if r.in_kev_catalog else "#1565C0" for r in items]

    fig.add_trace(
        go.Bar(x=[r.cve_id for r in cvss_ranked], y=[r.cvss_only_rank_score for r in cvss_ranked],
               marker_color=colors_for(cvss_ranked), text=[r.package for r in cvss_ranked], textposition="outside"),
        row=1, col=1,
    )
    fig.add_trace(
        go.Bar(x=[r.cve_id for r in multi_ranked], y=[r.multi_factor_score for r in multi_ranked],
               marker_color=colors_for(multi_ranked), text=[r.package for r in multi_ranked], textposition="outside"),
        row=1, col=2,
    )

    fig.add_trace(
        go.Scatter(
            x=[r.cvss_score for r in results], y=[r.epss_score for r in results],
            mode="markers+text", text=[r.package for r in results], textposition="top center",
            marker=dict(
                size=[max(10, r.multi_factor_score * 40) for r in results],
                color=["#B00020" if r.in_kev_catalog else "#5E35B1" for r in results],
            ),
        ),
        row=2, col=1,
    )

    fig.add_trace(
        go.Bar(
            x=["CVSS seul", "Multi-facteurs"],
            y=[comparison.kev_coverage_cvss_only, comparison.kev_coverage_multi_factor],
            marker_color=["#E65100", "#2E7D32"],
            text=[f"{comparison.kev_coverage_cvss_only:.0%}", f"{comparison.kev_coverage_multi_factor:.0%}"],
            textposition="outside",
        ),
        row=2, col=2,
    )

    fig.update_xaxes(title_text="CVSS (sévérité)", row=2, col=1)
    fig.update_yaxes(title_text="EPSS (probabilité d'exploitation)", row=2, col=1)
    fig.update_yaxes(title_text="Score", row=1, col=1)
    fig.update_yaxes(title_text="Score", row=1, col=2)
    fig.update_yaxes(title_text="Couverture KEV", range=[0, 1.1], row=2, col=2)

    fig.update_layout(
        title_text="Conformité CRA -- Priorisation multi-facteurs des vulnérabilités SBOM "
                    "(rouge = catalogue CISA KEV, exploitation confirmée)",
        height=800, showlegend=False, template="plotly_white",
    )

    fig.write_html(output_path, include_plotlyjs=True, full_html=True)
