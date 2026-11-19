#!/usr/bin/env python3
"""Compare deux modeles evalues avec evaluate.py et ecrit un tableau Markdown.

Usage :
  python evaluation/compare.py --a qwen2.5-3b_fp16 --b phi3.5-mini_fp16
Lit results/benchmark_<tag>.json et results/benchmark_<tag>_predictions.jsonl,
ecrit results/benchmark_comparison.md.
"""
import argparse
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(out_dir, tag):
    res = json.load(open(out_dir / f"benchmark_{tag}.json", encoding="utf-8"))
    preds = [json.loads(l) for l in open(out_dir / f"benchmark_{tag}_predictions.jsonl", encoding="utf-8")]
    return res, preds


def pct(x):
    return f"{x * 100:.1f} %"


def pct_ci(x, ci):
    return f"{x * 100:.1f} % [{ci[0] * 100:.0f}-{ci[1] * 100:.0f}]"


def mcnemar_p(b, c):
    """Test exact de McNemar : b et c = exemples reussis par un seul des deux modeles."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


def correctness(preds):
    ok = {}
    for p in preds:
        if p["task"] == "mcq":
            ok[(p["dataset"], p["id"])] = p["gold"] == p["pred"]
        else:
            ok[(p["dataset"], p["id"])] = p["gold_category"] == p["pred_category"]
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="tag du modele A (ex. qwen2.5-3b_fp16)")
    ap.add_argument("--b", required=True, help="tag du modele B (ex. phi3.5-mini_fp16)")
    ap.add_argument("--out-dir", type=Path, default=HERE.parent / "results")
    args = ap.parse_args()
    ra, pa = load(args.out_dir, args.a)
    rb, pb = load(args.out_dir, args.b)

    L = [f"# Benchmark {ra['model']} vs {rb['model']}", "",
         f"Précision FP16, décodage déterministe, prompt `{ra['prompt_version']}`, GPU {ra['gpu']}. "
         "Les intervalles [min-max] sont des intervalles de confiance à 95 % (Wilson).", ""]

    def table(title, rows):
        L.extend([f"## {title}", "", f"| Métrique | {ra['model']} | {rb['model']} |", "|---|---|---|"])
        L.extend(f"| {name} | {va} | {vb} |" for name, va, vb in rows)
        L.append("")

    table("QCM de culture cyber", [
        ("Accuracy", pct_ci(ra["mcq"]["accuracy"], ra["mcq"]["accuracy_ci95"]),
         pct_ci(rb["mcq"]["accuracy"], rb["mcq"]["accuracy_ci95"])),
        ("Réponses non interprétées", ra["mcq"]["unparsed"], rb["mcq"]["unparsed"]),
        ("Latence moyenne (s)", ra["mcq"]["latency"]["mean_s"], rb["mcq"]["latency"]["mean_s"])])

    for name in ra["alerts"]:
        a, b = ra["alerts"][name], rb["alerts"][name]
        table(f"Classification d'alertes : {name} ({a['n']} alertes)", [
            ("Accuracy de la catégorie", pct_ci(a["category_accuracy"], a["category_accuracy_ci95"]),
             pct_ci(b["category_accuracy"], b["category_accuracy_ci95"])),
            ("Macro-F1 de la catégorie", f"{a['category_macro_f1']:.3f}", f"{b['category_macro_f1']:.3f}"),
            ("Accuracy de la sévérité", pct(a["severity_accuracy"]), pct(b["severity_accuracy"])),
            ("Accuracy de la technique MITRE", pct(a["mitre_accuracy"]), pct(b["mitre_accuracy"])),
            ("Format de sortie invalide", pct(a["invalid_format_rate"]), pct(b["invalid_format_rate"])),
            ("Technique MITRE inexistante", pct(a["invalid_mitre_rate"]), pct(b["invalid_mitre_rate"])),
            ("Entités inventées dans l'explication", pct(a["unsupported_entity_rate"]), pct(b["unsupported_entity_rate"])),
            ("**Taux d'hallucination (global)**", pct(a["hallucination_rate"]), pct(b["hallucination_rate"])),
            ("Latence moyenne / p95 (s)", f"{a['latency']['mean_s']} / {a['latency']['p95_s']}",
             f"{b['latency']['mean_s']} / {b['latency']['p95_s']}"),
            ("Tokens/s (requête unique)", a["latency"]["mean_tokens_per_s"], b["latency"]["mean_tokens_per_s"])])

    mem = [("Temps de chargement (s)", ra["load_time_s"], rb["load_time_s"]),
           ("VRAM après chargement (Go)", ra["vram_after_load_gb"], rb["vram_after_load_gb"]),
           ("VRAM pic, requête unique (Go)", ra["peak_vram_gb"], rb["peak_vram_gb"])]
    for key in ra.get("throughput", {}):
        ta, tb = ra["throughput"][key], rb.get("throughput", {}).get(key)
        if tb:
            size = key.split("_")[1]
            mem += [(f"Débit, batch {size} (tokens/s)", ta["tokens_per_s"], tb["tokens_per_s"]),
                    (f"Débit, batch {size} (alertes/s)", ta["samples_per_s"], tb["samples_per_s"]),
                    (f"VRAM pic, batch {size} (Go)", ta["peak_vram_gb"], tb["peak_vram_gb"])]
    table("Mémoire et débit", mem)

    oa, ob = correctness(pa), correctness(pb)
    L.extend(["## Écarts statistiquement significatifs ?", "",
              "Test exact de McNemar sur les exemples bien classés (QCM : bonne lettre ; alertes : bonne catégorie).",
              "", "| Jeu de test | Réussis par A seulement | Réussis par B seulement | p-value |", "|---|---|---|---|"])
    for ds in sorted({d for d, _ in oa}):
        keys = [k for k in oa if k[0] == ds and k in ob]
        only_a = sum(oa[k] and not ob[k] for k in keys)
        only_b = sum(ob[k] and not oa[k] for k in keys)
        L.append(f"| {ds} | {only_a} | {only_b} | {mcnemar_p(only_a, only_b):.3f} |")
    L.extend(["", "Une p-value supérieure à 0,05 signifie que l'écart observé peut être dû au hasard "
              "(jeu de test de petite taille)."])

    text = "\n".join(L) + "\n"
    out = args.out_dir / "benchmark_comparison.md"
    out.write_text(text, encoding="utf-8")
    print(text)
    print(f"Tableau écrit dans {out}")


if __name__ == "__main__":
    main()
