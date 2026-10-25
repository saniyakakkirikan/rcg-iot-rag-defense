import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.retrieval.kb_lookup import get_description

PREDICTIONS = REPO_ROOT / "results" / "rf_ciciot_multiclass_v1_test_predictions.csv"
OUT_DIR = REPO_ROOT / "results" / "pipeline_demo"
DATASET = "ciciot2023"


def build_prompt(predicted_class, description, confidence):
    return (
        "You are helping a security analyst.\n"
        f"A classifier looked at one network flow and predicted: {predicted_class} "
        f"(model confidence: {confidence:.1%}).\n\n"
        f"Description of this class from our knowledge base:\n{description}\n\n"
        "Write a short threat report for the analyst in 3 to 4 sentences. "
        "Use only the description above. Do not add facts that are not in it."
    )


def pick_examples():
    correct_attack = benign = wrong = None
    with open(PREDICTIONS, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            true, pred = row["true_label"], row["predicted_label"]
            if correct_attack is None and true == pred and true != "BenignTraffic":
                correct_attack = row
            elif benign is None and true == pred == "BenignTraffic":
                benign = row
            elif wrong is None and true != pred:
                wrong = row
            if correct_attack and benign and wrong:
                break
    return [
        ("1_correct_attack", correct_attack),
        ("2_benign", benign),
        ("3_wrong_prediction", wrong),
    ]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for name, row in pick_examples():
        predicted = row["predicted_label"]
        confidence = float(row["confidence"])
        description = get_description(predicted, DATASET)
        prompt = build_prompt(predicted, description, confidence)

        (OUT_DIR / f"example_{name}_prompt.txt").write_text(prompt, encoding="utf-8")

        report_file = OUT_DIR / f"example_{name}_report.txt"
        report = ""
        if report_file.exists():
            report = report_file.read_text(encoding="utf-8").strip()

        results.append({
            "example": name,
            "row_in_deduped_sample": row["row_in_deduped_sample"],
            "true_label": row["true_label"],
            "predicted_label": predicted,
            "confidence": confidence,
            "description": description,
            "prompt": prompt,
            "report": report,
        })

        print("=" * 60)
        print(f"EXAMPLE {name}")
        print(f"true: {row['true_label']} | predicted: {predicted}")
        print(prompt)
        print("REPORT:", report if report else "(not saved yet)")

    out = OUT_DIR / "pipeline_demo_examples.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\nSaved:", out)


if __name__ == "__main__":
    main()