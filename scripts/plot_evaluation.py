"""Generate publication-quality Stage 2 evaluation figures from eval_<profile>.csv."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

PROFILE_STYLES = {
    "native": {"color": "#0072B2", "marker": "o", "linestyle": "-", "label": "Native (AES-NI + AVX2)"},
    "soft": {"color": "#D55E00", "marker": "s", "linestyle": "--", "label": "Software-Only (Scalar)"},
}

ALG_MAP = {
    "AES-128-GCM": 0,
    "ChaCha20-Poly1305": 1,
    "Ascon-AEAD128": 2,
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
            "legend.fontsize": 8.5,
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


def parse_delta(policy_label: str) -> float | None:
    if policy_label == "Adaptive(d=0.00)":
        return 0.0
    if policy_label.startswith("Adaptive+Hyst(d="):
        return float(policy_label.split("d=")[1].rstrip(")"))
    return None


def plot_hysteresis_tradeoff(
    native_rows: list[dict[str, str]],
    soft_rows: list[dict[str, str]],
    out_stem: Path,
) -> None:
    fig, (ax_sw, ax_reg) = plt.subplots(1, 2, figsize=(11.5, 4.5), layout="constrained")

    for profile, rows in [("native", native_rows), ("soft", soft_rows)]:
        st = PROFILE_STYLES[profile]
        mb = [r for r in rows if r["trace"] == "mixed_burst"]
        pts = []
        for r in mb:
            d = parse_delta(r["policy"])
            if d is not None:
                pts.append((d * 100.0, int(r["switch_count"]), float(r["regret_pct"])))
        pts.sort(key=lambda x: x[0])
        xs = [p[0] for p in pts]
        sw = [p[1] for p in pts]
        reg = [p[2] for p in pts]

        ax_sw.plot(xs, sw, label=st["label"], color=st["color"], marker=st["marker"], linestyle=st["linestyle"], lw=2.0)
        ax_reg.plot(xs, reg, label=st["label"], color=st["color"], marker=st["marker"], linestyle=st["linestyle"], lw=2.0)

    ax_sw.set_title("A. Switching Frequency vs Hysteresis Threshold")
    ax_sw.set_xlabel("Hysteresis Threshold δ (%)")
    ax_sw.set_ylabel("Algorithm Switches (count)")
    ax_sw.grid(axis="y", linestyle=":", lw=0.7, color="#CCCCCC")
    ax_sw.legend(loc="upper right")

    ax_reg.set_title("B. Performance Regret vs Hysteresis Threshold")
    ax_reg.set_xlabel("Hysteresis Threshold δ (%)")
    ax_reg.set_ylabel("Performance Regret vs Oracle (%)")
    ax_reg.grid(axis="y", linestyle=":", lw=0.7, color="#CCCCCC")
    ax_reg.legend(loc="upper left")

    fig.suptitle("Hysteresis Stability–Performance Trade-Off (Mixed Burst Trace)", fontsize=11.5, fontweight="bold")
    save_figure(fig, out_stem)
    plt.close(fig)


def plot_policy_comparison(
    native_rows: list[dict[str, str]],
    soft_rows: list[dict[str, str]],
    out_stem: Path,
) -> None:
    selected_policies = [
        "Static(AES-128-GCM)",
        "Static(ChaCha20-Poly1305)",
        "Static(Ascon-AEAD128)",
        "Adaptive(d=0.00)",
        "Adaptive+Hyst(d=0.15)",
    ]
    short_labels = ["Static\nAES-GCM", "Static\nChaCha20", "Static\nAscon", "Adaptive\n(δ=0%)", "Adaptive+Hyst\n(δ=15%)"]

    fig, (ax_nat, ax_soft) = plt.subplots(1, 2, figsize=(12.0, 4.6), layout="constrained")
    x = np.arange(len(selected_policies))

    for ax, title, rows in [
        (ax_nat, "A. Native Hardware Profile (AES-NI + AVX2)", native_rows),
        (ax_soft, "B. Pure-Software Scalar Profile", soft_rows),
    ]:
        mb = {r["policy"]: float(r["throughput_mb_s"]) for r in rows if r["trace"] == "mixed_burst"}
        vals = [mb[p] for p in selected_policies]
        colors = ["#666666", "#888888", "#AAAAAA", "#D55E00", "#0072B2"]
        bars = ax.bar(x, vals, width=0.58, color=colors, edgecolor="#222222", lw=0.8)
        ax.set_title(title)
        ax.set_ylabel("End-to-End Throughput (MB/s)")
        ax.set_xticks(x, short_labels)
        ax.set_ylim(0, max(vals) * 1.22 if vals else 1.0)
        ax.grid(axis="y", linestyle=":", lw=0.7, color="#CCCCCC")
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2.0, v + max(vals) * 0.02, f"{v:.1f}", ha="center", va="bottom", fontsize=8.0)

    fig.suptitle("Policy Throughput Comparison on Mixed Burst Workload", fontsize=11.5, fontweight="bold")
    save_figure(fig, out_stem)
    plt.close(fig)


def plot_selection_timeline(soft_tl: list[dict[str, str]], out_stem: Path) -> None:
    fig, (ax0, ax1) = plt.subplots(2, 1, figsize=(11.5, 5.4), sharex=True, layout="constrained")

    for ax, pol, title in [
        (ax0, "Adaptive(d=0.00)", "A. Adaptive without Hysteresis (δ = 0%) — Software Profile"),
        (ax1, "Adaptive+Hyst(d=0.15)", "B. Adaptive with Hysteresis (δ = 15%) — Software Profile"),
    ]:
        rows = [r for r in soft_tl if r["trace"] == "policy_shift" and r["policy"] == pol]
        steps = [int(r["step"]) for r in rows]
        algs = [ALG_MAP[r["chosen_alg"]] for r in rows]
        ax.axvspan(30, 59, color="#F0E442", alpha=0.25, label="256-bit Security Phase")
        ax.step(steps, algs, where="post", color="#0072B2", lw=1.8)
        ax.set_yticks([0, 1, 2], ["AES-128-GCM", "ChaCha20-Poly1305", "Ascon-AEAD128"])
        ax.set_ylim(-0.35, 2.35)
        ax.set_title(title)
        ax.grid(axis="x", linestyle=":", lw=0.6, color="#CCCCCC")
        ax.legend(loc="lower right")

    ax1.set_xlabel("Trace Step Index (0–89)")
    fig.suptitle("Per-Step Algorithm Selection & Security Override Timeline (Policy Shift Trace)", fontsize=11.5, fontweight="bold")
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
