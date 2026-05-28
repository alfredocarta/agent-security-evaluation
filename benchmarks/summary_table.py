#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


BENCHMARKS_DIR = Path("benchmarks")

DATASETS = [
    ("deepset", "deepset", "deepset_results_full.json"),
    ("jackhhao", "jackhhao", "jackhhao_results_full.json"),
    ("llm-sr", "llm-sem-router", "llm_semantic_router_results_full.json"),
    ("bipia", "bipia", "bipia_results_full.json"),
    ("mindgard", "mindgard", "mindgard_results_full.json"),
    ("neuralchemy", "neuralchemy", "neuralchemy_results_full.json"),
    ("opi", "opi", "open_prompt_injection_results_full.json"),
    ("safeguard", "safeguard", "safeguard_results_full.json"),
    ("toxic", "toxic-chat", "toxic_chat_results_full.json"),
    ("jailbreak", "jailbreakbench", "jailbreakbench_results_full.json"),
    ("spml", "spml", "spml_results_full.json"),
]

KEY_CONFIGS = [
    "ASF L1.5 only",
    "ASF Stage 1+2+2.5",
    "ASF Always-Stage25",
    "ONNX Prompt Guard 86M",
    "ASF L1.5 + ONNX (union)",
]


def normalize_row(row):
    return {
        "configuration": row["configuration"],
        "recall": row.get("recall"),
        "fpr": row.get("fpr"),
        "f1": row.get("f1"),
        "avg_latency_ms": row.get("avg_latency_ms"),
        "n_samples": row.get("n_samples"),
    }


def load_results(path):
    with open(path) as f:
        data = json.load(f)

    if isinstance(data, list):
        return [normalize_row(row) for row in data]

    if "results" in data:
        return [normalize_row(row) for row in data["results"]]

    if "original_sample" in data or "modified_sample" in data:
        return {
            "original_sample": [
                normalize_row(row) for row in data.get("original_sample", [])
            ],
            "modified_sample": [
                normalize_row(row) for row in data.get("modified_sample", [])
            ],
        }

    raise ValueError(f"Unsupported results structure: {path}")


def fmt_pct(value):
    if value is None:
        return "-"
    return f"{value * 100:.1f}%"


def fmt_recall_cell(value):
    if value is None:
        return "-"
    return f"{value * 100:.1f}"


def fmt_latency(value):
    if value is None:
        return "-"
    return f"{value:.1f}ms"


def fmt_int(value):
    if value is None:
        return "-"
    return str(value)


def md_cell(value):
    return "—" if value == "-" else value


def md_escape(value):
    return str(value).replace("|", "\\|")


def print_table(title, rows):
    print(title)
    print(
        f"{'Configuration':<35} {'Recall':>8} {'FPR':>8} "
        f"{'F1':>8} {'Lat':>10} {'N':>8}"
    )
    print("-" * 83)
    for row in rows:
        print(
            f"{row['configuration']:<35} "
            f"{fmt_pct(row.get('recall')):>8} "
            f"{fmt_pct(row.get('fpr')):>8} "
            f"{fmt_pct(row.get('f1')):>8} "
            f"{fmt_latency(row.get('avg_latency_ms')):>10} "
            f"{fmt_int(row.get('n_samples')):>8}"
        )
    print()


def row_by_config(rows):
    return {row["configuration"]: row for row in rows}


def mindgard_cell(results, config):
    original = row_by_config(results["original_sample"]).get(config)
    modified = row_by_config(results["modified_sample"]).get(config)
    original_recall = original.get("recall") if original else None
    modified_recall = modified.get("recall") if modified else None
    if original_recall is None and modified_recall is None:
        return "-"
    return f"{fmt_recall_cell(original_recall)}/{fmt_recall_cell(modified_recall)}"


def print_full_tables(loaded):
    print("Section 1 - Full table per dataset")
    print()
    for key, alias, _filename in DATASETS:
        results = loaded[key]
        if key == "mindgard":
            print_table(f"{alias} - original_sample", results["original_sample"])
            print_table(f"{alias} - modified_sample", results["modified_sample"])
        else:
            print_table(alias, results)


def print_cross_dataset_summary(loaded):
    print("Section 2 - Cross-dataset summary (key configs only)")
    print()

    headers = [alias for _key, alias, _filename in DATASETS]
    col_widths = [max(len(header), 8) for header in headers]
    config_width = max(len("Configuration"), max(len(config) for config in KEY_CONFIGS))

    print(
        f"{'Configuration':<{config_width}} "
        + " ".join(
            f"{header:>{width}}" for header, width in zip(headers, col_widths)
        )
    )
    print("-" * (config_width + 1 + sum(col_widths) + len(col_widths) - 1))

    indexed = {
        key: row_by_config(results)
        for key, _alias, _filename in DATASETS
        if key != "mindgard"
        for results in [loaded[key]]
    }

    for config in KEY_CONFIGS:
        cells = []
        for key, _alias, _filename in DATASETS:
            if key == "mindgard":
                cells.append(mindgard_cell(loaded[key], config))
                continue
            row = indexed[key].get(config)
            cells.append(fmt_recall_cell(row.get("recall") if row else None))

        print(
            f"{config:<{config_width}} "
            + " ".join(
                f"{cell:>{width}}" for cell, width in zip(cells, col_widths)
            )
        )


def render_markdown_table(headers, rows):
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _header in headers) + " |",
    ]
    for row in rows:
        lines.append(
            "| " + " | ".join(md_escape(cell) for cell in row) + " |"
        )
    return "\n".join(lines)


def render_full_markdown_table(title, rows):
    headers = ["Configuration", "Recall", "FPR", "F1", "Lat", "N"]
    markdown_rows = []
    for row in rows:
        markdown_rows.append(
            [
                row["configuration"],
                md_cell(fmt_pct(row.get("recall"))),
                md_cell(fmt_pct(row.get("fpr"))),
                md_cell(fmt_pct(row.get("f1"))),
                md_cell(fmt_latency(row.get("avg_latency_ms"))),
                md_cell(fmt_int(row.get("n_samples"))),
            ]
        )
    return f"### {title}\n\n{render_markdown_table(headers, markdown_rows)}"


def render_markdown(loaded):
    sections = ["## Section 1 - Full table per dataset"]

    for key, alias, _filename in DATASETS:
        results = loaded[key]
        if key == "mindgard":
            sections.append(
                render_full_markdown_table(
                    f"{alias} - original_sample", results["original_sample"]
                )
            )
            sections.append(
                render_full_markdown_table(
                    f"{alias} - modified_sample", results["modified_sample"]
                )
            )
        else:
            sections.append(render_full_markdown_table(alias, results))

    headers = ["Configuration"] + [alias for _key, alias, _filename in DATASETS]
    indexed = {
        key: row_by_config(results)
        for key, _alias, _filename in DATASETS
        if key != "mindgard"
        for results in [loaded[key]]
    }

    summary_rows = []
    for config in KEY_CONFIGS:
        row_cells = [config]
        for key, _alias, _filename in DATASETS:
            if key == "mindgard":
                row_cells.append(md_cell(mindgard_cell(loaded[key], config)))
                continue
            row = indexed[key].get(config)
            row_cells.append(
                md_cell(fmt_recall_cell(row.get("recall") if row else None))
            )
        summary_rows.append(row_cells)

    sections.append("## Section 2 - Cross-dataset summary (key configs only)")
    sections.append(render_markdown_table(headers, summary_rows))
    return "\n\n".join(sections) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="also write benchmarks/summary.md as GitHub-flavored markdown",
    )
    args = parser.parse_args()

    loaded = {
        key: load_results(BENCHMARKS_DIR / filename)
        for key, _alias, filename in DATASETS
    }
    print_full_tables(loaded)
    print_cross_dataset_summary(loaded)
    if args.markdown:
        (BENCHMARKS_DIR / "summary.md").write_text(render_markdown(loaded))


if __name__ == "__main__":
    main()
