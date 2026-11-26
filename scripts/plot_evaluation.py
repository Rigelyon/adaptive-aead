"""Generate publication-quality Stage 2 evaluation figures from multi-trial isolated CSVs."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

SERIES_STYLES = {
    ("native", "Lookup"): {"color": "#0072B2", "marker": "o", "linestyle": "-", "label": "Native — Static Lookup"},
    ("native", "EMA"): {"color": "#56B4E9", "marker": "s", "linestyle": "--", "label": "Native — Online EMA"},
    ("soft", "Lookup"): {"color": "#D55E00", "marker": "^", "linestyle": "-", "label": "Soft — Static Lookup"},
    ("soft", "EMA"): {"color": "#009E73", "marker": "D", "linestyle": "--", "label": "Soft — Online EMA"},
}

ALG_MAP = {
    "AES-128-GCM": 0,
    "AES-256-GCM": 1,
    "ChaCha20-Poly1305": 2,
    "Ascon-AEAD128": 3,
}


def configure_rcparams() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "font.family": "sans-serif",
            "font.sans-serif": ["DejaVu Sans", "Liberation Sans", "Arial"],
            "font.size": 9.5,
            "axes.titlesize": 10.5,
            "axes.titleweight": "bold",
            "axes.labelsize": 9.5,
            "xtick.labelsize": 8.5,
            "ytick.labelsize": 8.5,
            "legend.fontsize": 8.0,
            "legend.frameon": True,
            "legend.framealpha": 0.95,
            "legend.edgecolor": "#CCCCCC",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.edgecolor": "#333333",
            "axes.linewidth": 0.9,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_figure(fig: mpl.figure.Figure, stem: Path) -> None:
    stem.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(stem.with_suffix(".png"), dpi=300, facecolor="white")
    fig.savefig(stem.with_suffix(".pdf"), facecolor="white")


def parse_family_delta(policy_label: str) -> tuple[str, float] | None:
    if policy_label == "Lookup(d=0.00)":
        return ("Lookup", 0.0)
    if policy_label.startswith("Lookup+Hyst(d="):
        return ("Lookup", float(policy_label.split("d=")[1].rstrip(")")))
    if policy_label == "AdaptiveEMA(d=0.00)":
        return ("EMA", 0.0)
    if policy_label.startswith("AdaptiveEMA+Hyst(d="):
        return ("EMA", float(policy_label.split("d=")[1].rstrip(")")))
    return None


def plot_hysteresis_tradeoff(
    native_rows: list[dict[str, str]],
    soft_rows: list[dict[str, str]],
    out_stem: Path,
) -> None:
    """Plot Switching Frequency & Performance Regret vs Hysteresis Threshold (Memory domain)."""
    fig, (ax_sw, ax_reg) = plt.subplots(1, 2, figsize=(12.0, 4.7), layout="constrained")

    for profile, rows in [("native", native_rows), ("soft", soft_rows)]:
        mb = [r for r in rows if r["domain"] == "memory" and r["trace"] == "mixed_burst"]
        for family in ["Lookup", "EMA"]:
            st = SERIES_STYLES[(profile, family)]
            pts = []
            for r in mb:
                parsed = parse_family_delta(r["policy"])
                if parsed and parsed[0] == family:
                    d = parsed[1] * 100.0
                    sw = float(r["switch_count_median"])
                    reg = float(r["regret_median_pct"]) if r["regret_median_pct"] != "N/A" else np.nan
                    pts.append((d, sw, reg))
            pts.sort(key=lambda x: x[0])
            xs = [p[0] for p in pts]
            sw = [p[1] for p in pts]
            reg = [p[2] for p in pts]

            ax_sw.plot(xs, sw, label=st["label"], color=st["color"], marker=st["marker"], linestyle=st["linestyle"], lw=2.0)
            ax_reg.plot(xs, reg, label=st["label"], color=st["color"], marker=st["marker"], linestyle=st["linestyle"], lw=2.0)

    ax_sw.set_title("A. Median Switching Frequency vs Hysteresis Threshold")
    ax_sw.set_xlabel("Hysteresis Threshold δ (%)")
    ax_sw.set_ylabel("Algorithm Switches (median of 11 trials)")
    ax_sw.grid(axis="y", linestyle=":", lw=0.7, color="#CCCCCC")
    ax_sw.legend(loc="upper right")

    ax_reg.axhline(0.0, color="#666666", linestyle=":", lw=1.0)
    ax_reg.set_title("B. Median Performance Regret vs VBS Oracle")
    ax_reg.set_xlabel("Hysteresis Threshold δ (%)")
    ax_reg.set_ylabel("Performance Regret vs Oracle (%)")
    ax_reg.grid(axis="y", linestyle=":", lw=0.7, color="#CCCCCC")
    ax_reg.legend(loc="upper left")

    fig.suptitle("Hysteresis Stability–Performance Trade-Off (Memory Domain, Mixed Burst, n=11 Trials)", fontsize=11.5, fontweight="bold")
    save_figure(fig, out_stem)
    plt.close(fig)


def plot_policy_comparison(
    native_rows: list[dict[str, str]],
    soft_rows: list[dict[str, str]],
    out_stem: Path,
) -> None:
    """Plot Native and Soft Memory Policy-Shift and Disk-Batch Throughput Comparison with IQR error bars."""
    selected = [
        ("Static(AES-128-GCM)", "Static\nAES-128"),
        ("Static(AES-256-GCM)", "Static\nAES-256"),
        ("Static(ChaCha20-Poly1305)", "Static\nChaCha20"),
        ("Static(Ascon-AEAD128)", "Static\nAscon"),
        ("Lookup(d=0.00)", "Lookup\n(δ=0%)"),
        ("Lookup+Hyst(d=0.15)", "Lookup+Hyst\n(δ=15%)"),
        ("AdaptiveEMA+Hyst(d=0.15)", "EMA+Hyst\n(δ=15%)"),
    ]
    colors = ["#888888", "#666666", "#777777", "#999999", "#D55E00", "#0072B2", "#009E73"]

    fig, axes = plt.subplots(2, 2, figsize=(13.2, 8.2), layout="constrained")
    x = np.arange(len(selected))

    panels = [
        (axes[0, 0], "A. Native — Memory Policy-Shift (128→256→128 bit)", native_rows, "memory", "policy_shift"),
        (axes[0, 1], "B. Native — Disk-Batch Mixed-Burst", native_rows, "disk_batch", "mixed_burst"),
        (axes[1, 0], "C. Soft — Memory Policy-Shift (128→256→128 bit)", soft_rows, "memory", "policy_shift"),
        (axes[1, 1], "D. Soft — Disk-Batch Mixed-Burst", soft_rows, "disk_batch", "mixed_burst"),
    ]

    for ax, title, rows, domain, trace in panels:
        sub = {r["policy"]: r for r in rows if r["domain"] == domain and r["trace"] == trace}
        vals = [float(sub[k]["throughput_median_mb_s"]) for k, _ in selected]
        iqrs = [float(sub[k]["throughput_iqr_mb_s"]) / 2.0 for k, _ in selected]
        compliant = [sub[k]["policy_compliant"] == "true" for k, _ in selected]

        bars = ax.bar(x, vals, yerr=iqrs, capsize=3, width=0.58, color=colors, edgecolor="#222222", lw=0.8)
        for bar, v, ok in zip(bars, vals, compliant):
            if not ok:
                bar.set_hatch("//")
            tag = f"{v:.1f}" + ("\n(NC)" if not ok else "")
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                v + max(vals) * 0.045,
                tag,
                ha="center",
                va="bottom",
                fontsize=7.3,
                color="#B22222" if not ok else "#111111",
                fontweight="bold" if not ok else "normal",
            )

        ax.set_title(title)
        ax.set_ylabel("Median Throughput (MB/s ± IQR/2)")
        ax.set_xticks(x, [lbl for _, lbl in selected])
        ax.set_ylim(0, max(vals) * 1.30 if vals else 1.0)
        ax.grid(axis="y", linestyle=":", lw=0.7, color="#CCCCCC")

    fig.suptitle(
        "Compliant Throughput Comparison Across Native & Software Profiles (n=11 Trials; NC = Non-Compliant)",
        fontsize=11.5,
        fontweight="bold",
    )
    save_figure(fig, out_stem)
    plt.close(fig)


def plot_selection_timeline(soft_tl: list[dict[str, str]], out_stem: Path) -> None:
    """Plot per-step selection timeline on Memory Policy-Shift showing real SecurityOverride at step 240."""
    fig, (ax0, ax1) = plt.subplots(2, 1, figsize=(12.2, 5.6), sharex=True, layout="constrained")

    for ax, pol, title in [
        (ax0, "Lookup(d=0.00)", "A. Static Lookup without Hysteresis (δ = 0%) — Soft Profile (Memory)"),
        (ax1, "Lookup+Hyst(d=0.15)", "B. Static Lookup with Hysteresis (δ = 15%) — Soft Profile (Memory)"),
    ]:
        rows = [r for r in soft_tl if r["domain"] == "memory" and r["trace"] == "policy_shift" and r["policy"] == pol]
        steps = [int(r["step"]) for r in rows]
        algs = [ALG_MAP[r["chosen_alg"]] for r in rows]
        ov_steps = [int(r["step"]) for r in rows if r["reason"] == "security_override"]
        ov_algs = [ALG_MAP[r["chosen_alg"]] for r in rows if r["reason"] == "security_override"]

        ax.axvspan(240, 479, color="#F0E442", alpha=0.25, label="256-bit Security Phase (Steps 240–479)")
        ax.step(steps, algs, where="post", color="#0072B2", lw=1.6, label="Active Cipher")
        if ov_steps:
            ax.scatter(ov_steps, ov_algs, color="#D55E00", s=55, zorder=5, label=f"SecurityOverride (Step {ov_steps[0]})")
        ax.set_yticks([0, 1, 2, 3], ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "Ascon-AEAD128"])
        ax.set_ylim(-0.4, 3.4)
        ax.set_title(title)
        ax.grid(axis="x", linestyle=":", lw=0.6, color="#CCCCCC")
        ax.legend(loc="lower right")

    ax1.set_xlabel("Trace Step Index (0–719)")
    fig.suptitle("Algorithm Selection & SecurityOverride Timeline (Memory Policy-Shift Trace)", fontsize=11.5, fontweight="bold")
    save_figure(fig, out_stem)
    plt.close(fig)


def main() -> None:
    configure_rcparams()
    base = Path(__file__).resolve().parent.parent
    res = base / "results"
    figs = res / "figures"

    native_rows = load_csv(res / "eval_native.csv")
    soft_rows = load_csv(res / "eval_soft.csv")
    soft_tl = load_csv(res / "eval_soft_timeline.csv")

    plot_hysteresis_tradeoff(native_rows, soft_rows, figs / "fig3_hysteresis_tradeoff")
    plot_policy_comparison(native_rows, soft_rows, figs / "fig4_policy_comparison")
    plot_selection_timeline(soft_tl, figs / "fig5_selection_timeline")
    print(f"Generated Stage 2 evaluation figures in {figs}")


if __name__ == "__main__":
    main()
