#!/usr/bin/env python3
"""Evaluation d'un petit modele de langage (SLM) sur le jeu de test cyber.

Deux tests :
  1. QCM de culture cyber (data/qa_cyber.jsonl)      -> accuracy
  2. Classification d'alertes SOC (data/alerts_cyber.jsonl)
       -> accuracy et F1 de la categorie, accuracy de la severite,
          accuracy de la technique MITRE ATT&CK
Pour chaque test : latence moyenne / mediane / p95 et tokens par seconde.

Exemples :
  python evaluate.py --mock --tag mock                       (test sans GPU)
  python evaluate.py --model Qwen/Qwen2.5-3B-Instruct --tag qwen2.5-3b_fp16
  python evaluate.py --model microsoft/Phi-3.5-mini-instruct --tag phi3.5-mini_fp16
"""
import argparse
import json
import re
import statistics
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
CATEGORIES = ["brute_force", "port_scan", "sql_injection", "phishing",
              "ransomware", "data_exfiltration", "privilege_escalation", "benign"]
SEVERITIES = ["low", "medium", "high", "critical"]

SYSTEM_PROMPT = "You are a cybersecurity SOC assistant. Follow the requested output format exactly."


# ----------------------------------------------------------------- donnees
def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def validate(qa, alerts):
    """Verifie que les jeux de donnees sont coherents avant de lancer l'evaluation."""
    ids = [r["id"] for r in qa + alerts]
    assert len(ids) == len(set(ids)), "identifiants en double"
    for r in qa:
        assert len(r["options"]) == 4 and r["answer"] in "ABCD", f"QCM invalide : {r['id']}"
    for r in alerts:
        assert r["category"] in CATEGORIES, f"categorie inconnue : {r['id']}"
        assert r["severity"] in SEVERITIES, f"severite inconnue : {r['id']}"
        assert isinstance(r["mitre"], list) and r["mitre"], f"mitre invalide : {r['id']}"


# ----------------------------------------------------------------- metriques
def accuracy(y_true, y_pred):
    return sum(t == p for t, p in zip(y_true, y_pred)) / len(y_true) if y_true else 0.0


def classification_report(y_true, y_pred, labels):
    """Precision, rappel et F1 par classe + macro-F1 (moyenne des F1 par classe)."""
    report = {}
    for lab in labels:
        tp = sum(t == lab and p == lab for t, p in zip(y_true, y_pred))
        fp = sum(t != lab and p == lab for t, p in zip(y_true, y_pred))
        fn = sum(t == lab and p != lab for t, p in zip(y_true, y_pred))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        report[lab] = {"precision": round(prec, 3), "recall": round(rec, 3),
                       "f1": round(f1, 3), "support": tp + fn}
    with_support = [v["f1"] for v in report.values() if v["support"] > 0]
    macro_f1 = sum(with_support) / len(with_support) if with_support else 0.0
    return report, macro_f1


def latency_stats(latencies, n_tokens):
    if not latencies:
        return {}
    s = sorted(latencies)
    p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]
    tps = [n / l for n, l in zip(n_tokens, latencies) if l > 0]
    return {"mean_s": round(statistics.mean(latencies), 3),
            "median_s": round(statistics.median(latencies), 3),
            "p95_s": round(p95, 3),
            "mean_tokens_per_s": round(statistics.mean(tps), 1) if tps else 0.0}


# ----------------------------------------------------------------- parsing des reponses
def parse_mcq(text):
    """Extrait la lettre A/B/C/D de la reponse du modele (None si introuvable)."""
    t = text.strip()
    m = re.match(r"^\W*([ABCD])\b", t)
    if m:
        return m.group(1)
    m = re.search(r"(?i:answer|correct option|option)\s*(?:is|:)?\s*\(?([ABCD])\b", t)
    if m:
        return m.group(1)
    m = re.search(r"\b([ABCD])\)", t)
    return m.group(1) if m else None


def _first_keyword(text, words):
    low = text.lower()
    found = [(low.find(w), w) for w in words if w in low]
    return min(found)[1] if found else None


def parse_alert(text):
    """Extrait (categorie, severite, id MITRE, format_json_ok) de la reponse du modele."""
    cat = sev = mitre = None
    json_ok = False
    m = re.search(r"\{.*?\}", text, re.S)
    if m:
        try:
            d = json.loads(m.group(0))
            cat = str(d.get("category", "")).strip().lower().replace(" ", "_").replace("-", "_")
            sev = str(d.get("severity", "")).strip().lower()
            mitre = str(d.get("mitre", "")).strip()
            json_ok = True
        except json.JSONDecodeError:
            pass
    if cat not in CATEGORIES:
        cat = _first_keyword(text, CATEGORIES) or "unknown"
        json_ok = False
    if sev not in SEVERITIES:
        sev = _first_keyword(text, SEVERITIES) or "unknown"
        json_ok = False
    if mitre is None:
        mitre = text
    t = re.search(r"T\d{4}", mitre.upper())
    return cat, sev, (t.group(0) if t else "none"), json_ok


# ----------------------------------------------------------------- modeles
class HFModel:
    """Modele Hugging Face charge en FP16 sur le GPU."""

    def __init__(self, model_id):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_id, dtype=torch.float16, device_map="auto")
        self.generate(SYSTEM_PROMPT, "Say OK.", 5)  # echauffement : la 1re generation est plus lente
        torch.cuda.reset_peak_memory_stats()

    def generate(self, system, user, max_new_tokens):
        torch = self.torch
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        inputs = self.tok.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt", return_dict=True
        ).to(self.model.device)
        torch.cuda.synchronize()
        t0 = time.perf_counter()
        with torch.no_grad():
            out = self.model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
        torch.cuda.synchronize()
        latency = time.perf_counter() - t0
        new = out[0][inputs["input_ids"].shape[1]:]
        return self.tok.decode(new, skip_special_tokens=True), int(new.shape[0]), latency

    def peak_vram_gb(self):
        return round(self.torch.cuda.max_memory_allocated() / 1024 ** 3, 2)


class MockModel:
    """Faux modele pour tester le script sans GPU."""

    def generate(self, system, user, max_new_tokens):
        t0 = time.perf_counter()
        time.sleep(0.01)
        if "Answer with only the letter" in user:
            text = "B"
        else:
            text = '{"category": "brute_force", "severity": "high", "mitre": "T1110"}'
        return text, 10, time.perf_counter() - t0

    def peak_vram_gb(self):
        return 0.0


# ----------------------------------------------------------------- evaluations
def run_mcq(model, qa):
    preds, lats, toks = [], [], []
    for r in qa:
        opts = "\n".join(f"{'ABCD'[i]}) {o}" for i, o in enumerate(r["options"]))
        prompt = f"{r['question']}\n{opts}\nAnswer with only the letter (A, B, C or D)."
        text, n, lat = model.generate(SYSTEM_PROMPT, prompt, 8)
        preds.append({"id": r["id"], "gold": r["answer"], "pred": parse_mcq(text),
                      "raw": text, "latency_s": round(lat, 3)})
        lats.append(lat)
        toks.append(n)
    summary = {"n": len(qa),
               "accuracy": round(accuracy([p["gold"] for p in preds], [p["pred"] for p in preds]), 3),
               "unparsed": sum(p["pred"] is None for p in preds),
               "latency": latency_stats(lats, toks)}
    return summary, preds


def run_alerts(model, alerts):
    preds, lats, toks = [], [], []
    for r in alerts:
        prompt = (f"Classify this security alert.\nAlert: {r['alert']}\n"
                  f"Return ONLY a JSON object with these keys: "
                  f"\"category\" (one of {CATEGORIES}), "
                  f"\"severity\" (one of {SEVERITIES}), "
                  f"\"mitre\" (a MITRE ATT&CK technique ID such as T1110, or \"none\" if benign).")
        text, n, lat = model.generate(SYSTEM_PROMPT, prompt, 80)
        cat, sev, mitre, json_ok = parse_alert(text)
        preds.append({"id": r["id"], "gold_category": r["category"], "pred_category": cat,
                      "gold_severity": r["severity"], "pred_severity": sev,
                      "gold_mitre": r["mitre"], "pred_mitre": mitre,
                      "json_ok": json_ok, "raw": text, "latency_s": round(lat, 3)})
        lats.append(lat)
        toks.append(n)
    gold_c = [p["gold_category"] for p in preds]
    pred_c = [p["pred_category"] for p in preds]
    per_class, macro_f1 = classification_report(gold_c, pred_c, CATEGORIES)
    n = len(preds)
    summary = {"n": n,
               "category_accuracy": round(accuracy(gold_c, pred_c), 3),
               "category_macro_f1": round(macro_f1, 3),
               "per_class": per_class,
               "severity_accuracy": round(accuracy([p["gold_severity"] for p in preds],
                                                    [p["pred_severity"] for p in preds]), 3),
               "mitre_accuracy": round(sum(p["pred_mitre"] in p["gold_mitre"] for p in preds) / n, 3),
               "invalid_format_rate": round(sum(not p["json_ok"] for p in preds) / n, 3),
               "latency": latency_stats(lats, toks)}
    return summary, preds


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", help="identifiant Hugging Face du modele")
    ap.add_argument("--tag", required=True, help="nom court de l'experience (ex. qwen2.5-3b_fp16)")
    ap.add_argument("--mock", action="store_true", help="faux modele, sans GPU (test du script)")
    ap.add_argument("--data-dir", type=Path, default=HERE / "data")
    ap.add_argument("--out-dir", type=Path, default=HERE.parent / "results")
    ap.add_argument("--limit", type=int, default=None, help="ne tester que les N premiers exemples")
    args = ap.parse_args()
    if not args.mock and not args.model:
        ap.error("--model est obligatoire (sauf avec --mock)")

    qa = load_jsonl(args.data_dir / "qa_cyber.jsonl")
    alerts = load_jsonl(args.data_dir / "alerts_cyber.jsonl")
    validate(qa, alerts)
    if args.limit:
        qa, alerts = qa[:args.limit], alerts[:args.limit]

    model = MockModel() if args.mock else HFModel(args.model)
    print(f"== QCM ({len(qa)} questions)")
    mcq_sum, mcq_preds = run_mcq(model, qa)
    print(f"== Alertes ({len(alerts)} alertes)")
    alert_sum, alert_preds = run_alerts(model, alerts)

    result = {"tag": args.tag, "model": "mock" if args.mock else args.model,
              "date": datetime.now().isoformat(timespec="seconds"),
              "peak_vram_gb": model.peak_vram_gb(),
              "mcq": mcq_sum, "alerts": alert_sum}
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with open(args.out_dir / f"eval_{args.tag}.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    with open(args.out_dir / f"eval_{args.tag}_predictions.jsonl", "w", encoding="utf-8") as f:
        for p in [{"task": "mcq", **x} for x in mcq_preds] + [{"task": "alert", **x} for x in alert_preds]:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    print(f"\nQCM      : accuracy = {mcq_sum['accuracy']:.1%}  | latence moy. = {mcq_sum['latency']['mean_s']} s")
    print(f"Alertes  : categorie acc = {alert_sum['category_accuracy']:.1%} | macro-F1 = {alert_sum['category_macro_f1']:.3f}"
          f" | severite acc = {alert_sum['severity_accuracy']:.1%} | MITRE acc = {alert_sum['mitre_accuracy']:.1%}")
    print(f"           format invalide = {alert_sum['invalid_format_rate']:.1%} | latence moy. = {alert_sum['latency']['mean_s']} s"
          f" | {alert_sum['latency']['mean_tokens_per_s']} tokens/s | VRAM pic = {result['peak_vram_gb']} Go")
    print(f"Resultats ecrits dans {args.out_dir / ('eval_' + args.tag + '.json')}")


if __name__ == "__main__":
    main()
