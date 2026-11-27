"""Render precision–recall and ROC curves from aggregate Gemini study metrics."""

import argparse
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import PercentFormatter


SERIES = (
    ("deconfounded_multiview_stack", "prior_dev", "Multi-view on manual development", "#246A73", "-"),
    ("deconfounded_multiview_stack", "mixed_holdout", "Multi-view on grouped holdout", "#7654A6", "-"),
    (
        "deconfounded_multiview_stack",
        "unscored_archive_sms",
        "Multi-view on phishing archive + benign SMS",
        "#B64B23",
        "-",
    ),
    ("structure_plus", "prior_dev", "Structure Plus on manual development", "#4B5563", "--"),
)


def plot(metrics, output):
    fig, (pr, roc) = plt.subplots(1, 2, figsize=(11, 5.7))
    fig.patch.set_facecolor("#FFFFFF")
    fig.subplots_adjust(left=0.08, right=0.97, bottom=0.29, top=0.76, wspace=0.31)
    text = "#172736"
    fig.text(0.08, 0.925, "SentinelAI email classifier evaluation", fontsize=19, weight="bold", color=text)
    fig.text(
        0.08,
        0.865,
        "The same classifiers show different trade-offs across email collections.",
        fontsize=10,
        color="#475569",
    )

    for axis in (pr, roc):
        axis.set_xlim(0, 1)
        axis.set_ylim(0, 1.02)
        axis.xaxis.set_major_formatter(PercentFormatter(1, decimals=0))
        axis.yaxis.set_major_formatter(PercentFormatter(1, decimals=0))
        axis.spines[["top", "right"]].set_visible(False)
        axis.spines[["left", "bottom"]].set_color("#CBD5E1")
        axis.tick_params(length=3, colors="#475569")
        axis.grid(axis="y", color="#E6ECF2", linewidth=0.75)
        axis.set_axisbelow(True)

    pr.set_title("Precision–recall", loc="left", fontsize=12, weight="bold", color=text)
    pr.set(xlabel="Recall", ylabel="Precision")
    roc.set_title("Receiver operating characteristic", loc="left", fontsize=12, weight="bold", color=text)
    roc.set(xlabel="False-positive rate", ylabel="Recall")
    roc.axvspan(0, 0.05, color="#E2E8F0", linewidth=0)
    roc.plot([0, 1], [0, 1], linestyle=":", linewidth=1, color="#94A3B8", zorder=1)

    legend = []
    for model, cohort, label, color, style in SERIES:
        candidate = metrics["candidates"][model]
        curve = candidate["curves"][cohort]
        # The ledger stores fixed and validation-selected thresholds in ascending
        # order. Reverse once so recall and FPR increase along the paths.
        points = list(zip(curve["recall"], curve["precision"], curve["fpr"]))[::-1]
        recall, precision = zip(*((r, p) for r, p, _ in points if r is not None and p is not None))
        pr.plot(recall, precision, color=color, linestyle=style, linewidth=1.65)
        recall, fpr = zip(*((r, f) for r, _, f in points if r is not None and f is not None))
        roc.plot(fpr, recall, color=color, linestyle=style, linewidth=1.65)
        result = candidate["selected"]["cohorts"][cohort]["alerts"]
        if result["precision"] is not None:
            pr.scatter(
                result["recall"],
                result["precision"],
                s=37,
                c=color,
                edgecolors="white",
                linewidths=0.8,
                zorder=5,
                clip_on=False,
            )
        roc.scatter(
            result["fpr"],
            result["recall"],
            s=37,
            c=color,
            edgecolors="white",
            linewidths=0.8,
            zorder=5,
            clip_on=False,
        )
        legend.append(
            Line2D([0], [0], color=color, linestyle=style, linewidth=1.7, label=f"{label} · n={curve['n']:,}")
        )

    fig.legend(
        handles=legend,
        loc="lower left",
        bbox_to_anchor=(0.074, 0.12),
        ncol=2,
        frameon=False,
        labelcolor=text,
        fontsize=9,
    )
    fig.text(
        0.08,
        0.079,
        "Dots mark validation-selected caution cutoffs. Gray shading marks false-positive rates up to 5%.",
        fontsize=8.5,
        color="#475569",
    )
    fig.text(
        0.08,
        0.043,
        "The archive + SMS cohort has different sources for the two classes. The manual set has been evaluated before.",
        fontsize=8.5,
        color="#475569",
    )
    fig.savefig(output, dpi=160)
    plt.close(fig)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metrics", type=argparse.FileType("r"))
    parser.add_argument("output")
    args = parser.parse_args()
    plot(json.load(args.metrics), args.output)
