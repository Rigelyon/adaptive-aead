"""Generate publication-quality pilot benchmark figures from results/pilot_benchmark.csv."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

# Okabe-Ito colorblind-safe palette on white background with redundant encodings
ALG_ORDER = ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "Ascon-AEAD128"]
ALG_STYLES = {
    "AES-128-GCM": {"color": "#0072B2", "marker": "o", "linestyle": "-", "hatch": ""},
    "AES-256-GCM": {"color": "#56B4E9", "marker": "D", "linestyle": ":", "hatch": "xx"},
    "ChaCha20-Poly1305": {"color": "#D55E00", "marker": "s", "linestyle": "--", "hatch": "//"},
    "Ascon-AEAD128": {"color": "#009E73", "marker": "^", "linestyle": "-.", "hatch": ".."},
}

SIZE_LABELS = {
    64: "64 B",
    1024: "1 KB",
    4096: "4 KB",
    16384: "16 KB",
    65536: "64 KB",
    1048576: "1 MB",
    16777216: "16 MB",
    67108864: "64 MB",
}

DISK_SCENARIO_LABELS = {
    "disk_batch_small_200x4KB": "Batch Small\n(200 × 4 KB)",
    "disk_medium_8x2MB": "Medium\n(8 × 2 MB)",
    "disk_large_1x64MB": "Large\n(1 × 64 MB)",
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


def load_csv(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_figure(fig: mpl.figure.Figure, out_stem: Path) -> None:
    out_stem.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_stem.with_suffix(".png"), dpi=300, facecolor="white")
    fig.savefig(out_stem.with_suffix(".pdf"), facecolor="white")


def plot_in_memory_profile(rows: list[dict[str, str]], out_stem: Path) -> None:
    in_mem = [r for r in rows if r["phase"] == "in_memory"]
    sizes = sorted({int(r["size_bytes"]) for r in in_mem})
    x = np.arange(len(sizes))
    x_labels = [SIZE_LABELS.get(s, str(s)) for s in sizes]

    fig, (ax_tp, ax_lat) = plt.subplots(1, 2, figsize=(12.0, 4.7), layout="constrained")

    max_tp = 0.0
    for alg in ALG_ORDER:
        style = ALG_STYLES[alg]
        alg_rows = {int(r["size_bytes"]): r for r in in_mem if r["algorithm"] == alg}
        enc_tp = [float(alg_rows[s]["enc_mb_s"]) for s in sizes]
        enc_us = [float(alg_rows[s]["enc_ns"]) / 1000.0 for s in sizes]
        max_tp = max(max_tp, max(enc_tp))

        ax_tp.plot(
            x, enc_tp, label=alg, color=style["color"], marker=style["marker"],
            linestyle=style["linestyle"], linewidth=2.0, markersize=5.8,
        )
        ax_lat.plot(
            x, enc_us, label=alg, color=style["color"], marker=style["marker"],
            linestyle=style["linestyle"], linewidth=2.0, markersize=5.8,
        )

    ax_tp.set_title("A. In-Memory Encryption Throughput")
    ax_tp.set_xlabel("Payload Size")
    ax_tp.set_ylabel("Throughput (MB/s)")
    ax_tp.set_xticks(x, x_labels, rotation=25, ha="right")
    ax_tp.set_ylim(0, max_tp * 1.15)
    ax_tp.grid(axis="y", linestyle=":", linewidth=0.7, color="#CCCCCC")
    ax_tp.legend(loc="upper left")

    ax_tp.annotate(
        "Ascon > ChaCha20\n(64 B – 1 KB)",
        xy=(1.0, 521.0),
        xytext=(2.35, 160.0),
        fontsize=8.0,
        color="#222222",
        arrowprops=dict(arrowstyle="->", color="#444444", lw=1.0, connectionstyle="arc3,rad=-0.12"),
        bbox=dict(boxstyle="round,pad=0.25", fc="#F7F7F7", ec="#BBBBBB", lw=0.7),
    )

    ax_lat.set_title("B. In-Memory Encryption Latency (Log₁₀ Scale)")
    ax_lat.set_xlabel("Payload Size")
    ax_lat.set_ylabel("Median Latency (µs, log scale)")
    ax_lat.set_yscale("log")
    ax_lat.set_xticks(x, x_labels, rotation=25, ha="right")
    ax_lat.grid(axis="y", which="major", linestyle=":", linewidth=0.7, color="#CCCCCC")
    ax_lat.legend(loc="upper left")

    fig.suptitle(
        "Pilot In-Memory AEAD Performance Profile (Ryzen 5 5600H, AES-NI & AVX2 Enabled)",
        fontsize=11.5, fontweight="bold",
    )
    save_figure(fig, out_stem)
    plt.close(fig)


def plot_init_and_disk_profile(rows: list[dict[str, str]], out_stem: Path) -> None:
    init_rows = {r["algorithm"]: float(r["enc_ns"]) for r in rows if r["phase"] == "init"}
    disk_scenarios = [
        "disk_batch_small_200x4KB",
        "disk_medium_8x2MB",
        "disk_large_1x64MB",
    ]
    disk_map = {(r["phase"], r["algorithm"]): r for r in rows if r["phase"].startswith("disk_")}

    fig, (ax_init, ax_disk) = plt.subplots(
        1, 2, figsize=(12.2, 4.7), gridspec_kw={"width_ratios": [1.0, 1.55]}, layout="constrained"
    )

    x_init = np.arange(len(ALG_ORDER))
    init_vals = [init_rows[alg] for alg in ALG_ORDER]
    bars = ax_init.bar(
        x_init, init_vals, width=0.55,
        color=[ALG_STYLES[a]["color"] for a in ALG_ORDER],
        hatch=[ALG_STYLES[a]["hatch"] for a in ALG_ORDER],
        edgecolor="#222222", linewidth=0.8,
    )
    ax_init.set_title("A. Key Schedule Init Overhead (KeyInit::new)")
    ax_init.set_ylabel("Mean Initialization Time (ns)")
    ax_init.set_xticks(x_init, ["AES-128-\nGCM", "AES-256-\nGCM", "ChaCha20-\nPoly1305", "Ascon-\nAEAD128"])
    ax_init.set_ylim(0, max(init_vals) * 1.22)
    ax_init.grid(axis="y", linestyle=":", linewidth=0.7, color="#CCCCCC")

    for bar, val in zip(bars, init_vals):
        ax_init.text(
            bar.get_x() + bar.get_width() / 2.0, val + 1.5, f"{val:.1f} ns",
            ha="center", va="bottom", fontsize=8.0, fontweight="bold",
        )

    x_sc = np.arange(len(disk_scenarios))
    bar_w = 0.19
    max_disk = 0.0
    for idx, alg in enumerate(ALG_ORDER):
        style = ALG_STYLES[alg]
        offset = (idx - 1.5) * bar_w
        enc_vals = [float(disk_map[(sc, alg)]["enc_mb_s"]) for sc in disk_scenarios]
        max_disk = max(max_disk, max(enc_vals))
        b = ax_disk.bar(
            x_sc + offset, enc_vals, width=bar_w, label=alg,
            color=style["color"], hatch=style["hatch"], edgecolor="#222222", linewidth=0.8,
        )
        for rect, v in zip(b, enc_vals):
            ax_disk.text(
                rect.get_x() + rect.get_width() / 2.0, v + 22, f"{v:.0f}",
                ha="center", va="bottom", fontsize=7.0,
            )

    ax_disk.set_title("B. Disk File Encryption Throughput (Median of 5 Rotated Trials)")
    ax_disk.set_ylabel("End-to-End Throughput (MB/s)")
    ax_disk.set_xticks(x_sc, [DISK_SCENARIO_LABELS[s] for s in disk_scenarios])
    ax_disk.set_ylim(0, max_disk * 1.2)
    ax_disk.grid(axis="y", linestyle=":", linewidth=0.7, color="#CCCCCC")
    ax_disk.legend(loc="upper right")

    fig.suptitle(
        "Cipher Initialization Cost vs End-to-End Disk Processing (Multi-Trial Median)",
        fontsize=11.5, fontweight="bold",
    )
    save_figure(fig, out_stem)
    plt.close(fig)


def main() -> None:
    configure_rcparams()
    base_dir = Path(__file__).resolve().parent.parent
    csv_path = base_dir / "results" / "pilot_benchmark.csv"
    fig_dir = base_dir / "results" / "figures"

    rows = load_csv(csv_path)
    plot_in_memory_profile(rows, fig_dir / "fig1_in_memory_profile")
    plot_init_and_disk_profile(rows, fig_dir / "fig2_init_and_disk_profile")
    print(f"Generated figures in {fig_dir}")


if __name__ == "__main__":
    main()
