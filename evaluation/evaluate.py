#!/usr/bin/env python3
"""Benchmark d'un petit modele de langage (SLM) sur le jeu de test cyber (semaine 3).

Jeux de test (dossier data/) :
  - qa_cyber.jsonl          30 QCM de culture cyber
  - alerts_cyber.jsonl      40 alertes redigees a la main (Fati)
  - alerts_soc_logs.jsonl   40 alertes issues de flux reseau et de logs (Sakina)

Metriques :
  - QCM : accuracy (+ intervalle de confiance a 95 %)
  - Alertes : accuracy et macro-F1 de la categorie, accuracy de la severite et de la
    technique MITRE ATT&CK, taux de format invalide
  - Hallucination : technique MITRE inexistante, entite (IP, CVE, nom de machine) citee
    dans l'explication mais absente de l'alerte, et taux global
  - Latence (moyenne, mediane, p95), tokens/s, debit en batch, memoire GPU

Exemples :
  python evaluate.py --mock --tag mock                         (test sans GPU)
  python evaluate.py --model Qwen/Qwen2.5-3B-Instruct --tag qwen2.5-3b_fp16
  python evaluate.py --model microsoft/Phi-3.5-mini-instruct --tag phi3.5-mini_fp16
"""
import argparse
import json
import math
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
PROMPT_VERSION = "v2-explanation"
DEFAULT_ALERT_FILES = ["alerts_cyber.jsonl", "alerts_soc_logs.jsonl"]


# ----------------------------------------------------------------- donnees
def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_alerts(path):
    """Charge un fichier d'alertes ; 'mitre' peut etre une chaine ou une liste."""
    alerts = load_jsonl(path)
    for r in alerts:
        if isinstance(r["mitre"], str):
            r["mitre"] = [r["mitre"]]
    return alerts


def load_valid_mitre(path):
    """IDs ATT&CK valides (techniques et sous-techniques), un par ligne, nom apres une tabulation."""
    ids = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                ids.add(line.split("\t")[0].strip())
    return ids


def validate(qa, alert_sets):
    for r in qa:
        assert len(r["options"]) == 4 and r["answer"] in "ABCD", f"QCM invalide : {r['id']}"
    for name, alerts in alert_sets.items():
        ids = [r["id"] for r in alerts]
        assert len(ids) == len(set(ids)), f"{name} : identifiants en double"
        for r in alerts:
            assert r["category"] in CATEGORIES, f"{name} : categorie inconnue ({r['id']})"
            assert r["severity"] in SEVERITIES, f"{name} : severite inconnue ({r['id']})"
            assert r["mitre"], f"{name} : mitre vide ({r['id']})"


# ----------------------------------------------------------------- metriques
def accuracy(y_true, y_pred):
    return sum(t == p for t, p in zip(y_true, y_pred)) / len(y_true) if y_true else 0.0


def wilson_ci(k, n, z=1.96):
    """Intervalle de confiance a 95 % (Wilson) pour une proportion k/n."""
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - m) / d, 3), round((c + m) / d, 3)]


def classification_report(y_true, y_pred, labels):
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
    return report, (sum(with_support) / len(with_support) if with_support else 0.0)


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


def _field(text, key):
    m = re.search(r'"%s"\s*:\s*"([^"]*)"' % key, text)
    return m.group(1) if m else None


def parse_alert(text):
    """Extrait categorie, severite, ID MITRE, explication et validite du format JSON."""
    d = None
    for pat in (r"\{.*\}", r"\{.*?\}"):
        m = re.search(pat, text, re.S)
        if m:
            try:
                d = json.loads(m.group(0))
                break
            except json.JSONDecodeError:
                pass
    json_ok = isinstance(d, dict)
    if not json_ok:
        d = {k: _field(text, k) for k in ("category", "severity", "mitre", "explanation")}
    cat = str(d.get("category") or "").strip().lower().replace(" ", "_").replace("-", "_")
    sev = str(d.get("severity") or "").strip().lower()
    mitre = str(d.get("mitre") or "")
    explanation = str(d.get("explanation") or "")
    if cat not in CATEGORIES:
        cat = _first_keyword(text, CATEGORIES) or "unknown"
        json_ok = False
    if sev not in SEVERITIES:
        sev = _first_keyword(text, SEVERITIES) or "unknown"
        json_ok = False
    t = re.search(r"T\d{4}(?:\.\d{3})?", (mitre or text).upper())
    mitre_full = t.group(0) if t else "none"
    return {"category": cat, "severity": sev, "mitre": mitre_full,
            "explanation": explanation, "format_ok": json_ok}


# ----------------------------------------------------------------- hallucinations
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
HOST = re.compile(r"\b[A-Za-z]{2,}-[A-Za-z]*\d+[A-Za-z0-9-]*\b")


def unsupported_entities(explanation, alert_text):
    """Entites (IP, CVE, nom de machine) citees dans l'explication mais absentes de l'alerte."""
    low = alert_text.lower()
    ents = IPV4.findall(explanation) + CVE.findall(explanation)
    ents += HOST.findall(CVE.sub(" ", explanation))
    return sorted({e for e in ents if e.lower() not in low})


# ----------------------------------------------------------------- modeles
class HFModel:
    """Modele Hugging Face charge en FP16 sur le GPU."""

    def __init__(self, model_id):
        import torch
        from huggingface_hub import snapshot_download
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        snapshot_download(model_id)  # telechargement hors chronometre
        t0 = time.perf_counter()
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.tok.padding_side = "left"
        if self.tok.pad_token is None:
            self.tok.pad_token = self.tok.eos_token
        self.model = AutoModelForCausalLM.from_pretrained(
            model_id, dtype=torch.float16, device_map="auto")
        torch.cuda.synchronize()
        self.load_time_s = round(time.perf_counter() - t0, 1)
        self.vram_after_load_gb = round(torch.cuda.memory_allocated() / 1024 ** 3, 2)
        self.gpu = torch.cuda.get_device_name(0)
        self.generate(SYSTEM_PROMPT, "Say OK.", 5)  # echauffement
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

    def generate_batch(self, system, users, max_new_tokens):
        """Genere pour plusieurs prompts a la fois ; renvoie (tokens generes, duree)."""
        torch = self.torch
        texts = [self.tok.apply_chat_template(
            [{"role": "system", "content": system}, {"role": "user", "content": u}],
            tokenize=False, add_generation_prompt=True) for u in users]
        enc = self.tok(texts, return_tensors="pt", padding=True,
                       add_special_tokens=False).to(self.model.device)
        torch.cuda.synchronize()
        t0 = time.perf_counter()
        with torch.no_grad():
            out = self.model.generate(**enc, max_new_tokens=max_new_tokens, do_sample=False,
                                      pad_token_id=self.tok.pad_token_id)
        torch.cuda.synchronize()
        elapsed = time.perf_counter() - t0
        new = out[:, enc["input_ids"].shape[1]:]
        return int((new != self.tok.pad_token_id).sum()), elapsed

    def reset_peak(self):
        self.torch.cuda.reset_peak_memory_stats()

    def peak_vram_gb(self):
        return round(self.torch.cuda.max_memory_allocated() / 1024 ** 3, 2)


class MockModel:
    """Faux modele pour tester le script sans GPU."""
    load_time_s = 0.0
    vram_after_load_gb = 0.0
    gpu = "mock"

    def generate(self, system, user, max_new_tokens):
        t0 = time.perf_counter()
        time.sleep(0.01)
        if "Answer with only the letter" in user:
            text = "B"
        else:
            text = ('{"category": "brute_force", "severity": "high", "mitre": "T1110", '
                    '"explanation": "Repeated failed logins from 10.9.9.9 on host srv-x1."}')
        return text, 10, time.perf_counter() - t0

    def generate_batch(self, system, users, max_new_tokens):
        time.sleep(0.01)
        return 10 * len(users), 0.01 + 0.002 * len(users)

    def reset_peak(self):
        pass

    def peak_vram_gb(self):
        return 0.0


# ----------------------------------------------------------------- evaluations
def alert_prompt(alert_text):
    return (f"Classify this security alert.\nAlert: {alert_text}\n"
            f"Return ONLY a JSON object with these keys: "
            f"\"category\" (one of {CATEGORIES}), "
            f"\"severity\" (one of {SEVERITIES}), "
            f"\"mitre\" (a MITRE ATT&CK technique ID such as T1110, or \"none\" if benign), "
            f"\"explanation\" (one short sentence, at most 25 words, using only facts from the alert).")


def run_mcq(model, qa):
    preds, lats, toks = [], [], []
    for r in qa:
        opts = "\n".join(f"{'ABCD'[i]}) {o}" for i, o in enumerate(r["options"]))
        prompt = f"{r['question']}\n{opts}\nAnswer with only the letter (A, B, C or D)."
        text, n, lat = model.generate(SYSTEM_PROMPT, prompt, 8)
        preds.append({"dataset": "qa_cyber", "task": "mcq", "id": r["id"], "gold": r["answer"],
                      "pred": parse_mcq(text), "raw": text, "latency_s": round(lat, 3)})
        lats.append(lat)
        toks.append(n)
    k = sum(p["gold"] == p["pred"] for p in preds)
    summary = {"n": len(qa), "accuracy": round(k / len(qa), 3), "accuracy_ci95": wilson_ci(k, len(qa)),
               "unparsed": sum(p["pred"] is None for p in preds),
               "latency": latency_stats(lats, toks)}
    return summary, preds


def run_alerts(model, name, alerts, valid_ids):
    preds, lats, toks = [], [], []
    for r in alerts:
        text, n, lat = model.generate(SYSTEM_PROMPT, alert_prompt(r["alert"]), 150)
        p = parse_alert(text)
        unsupported = unsupported_entities(p["explanation"], r["alert"])
        invalid_mitre = p["mitre"] != "none" and p["mitre"] not in valid_ids
        preds.append({"dataset": name, "task": "alert", "id": r["id"],
                      "gold_category": r["category"], "pred_category": p["category"],
                      "gold_severity": r["severity"], "pred_severity": p["severity"],
                      "gold_mitre": r["mitre"], "pred_mitre": p["mitre"],
                      "format_ok": p["format_ok"], "explanation": p["explanation"],
                      "unsupported_entities": unsupported, "invalid_mitre": invalid_mitre,
                      "raw": text, "latency_s": round(lat, 3)})
        lats.append(lat)
        toks.append(n)
    n = len(preds)
    gold_c = [p["gold_category"] for p in preds]
    pred_c = [p["pred_category"] for p in preds]
    per_class, macro_f1 = classification_report(gold_c, pred_c, CATEGORIES)
    k_cat = sum(g == q for g, q in zip(gold_c, pred_c))
    k_sev = sum(p["gold_severity"] == p["pred_severity"] for p in preds)
    k_mit = sum(p["pred_mitre"].split(".")[0] in p["gold_mitre"] for p in preds)
    summary = {"n": n,
               "category_accuracy": round(k_cat / n, 3), "category_accuracy_ci95": wilson_ci(k_cat, n),
               "category_macro_f1": round(macro_f1, 3), "per_class": per_class,
               "severity_accuracy": round(k_sev / n, 3),
               "mitre_accuracy": round(k_mit / n, 3),
               "invalid_format_rate": round(sum(not p["format_ok"] for p in preds) / n, 3),
               "invalid_mitre_rate": round(sum(p["invalid_mitre"] for p in preds) / n, 3),
               "unsupported_entity_rate": round(sum(bool(p["unsupported_entities"]) for p in preds) / n, 3),
               "hallucination_rate": round(sum(p["invalid_mitre"] or bool(p["unsupported_entities"])
                                               for p in preds) / n, 3),
               "latency": latency_stats(lats, toks)}
    return summary, preds


def run_throughput(model, prompts, batch_sizes, max_new_tokens=60):
    result = {}
    for bs in batch_sizes:
        model.reset_peak()
        total_tok, total_t = 0, 0.0
        for i in range(0, len(prompts), bs):
            n, t = model.generate_batch(SYSTEM_PROMPT, prompts[i:i + bs], max_new_tokens)
            total_tok += n
            total_t += t
        result[f"batch_{bs}"] = {"samples_per_s": round(len(prompts) / total_t, 2),
                                 "tokens_per_s": round(total_tok / total_t, 1),
                                 "total_time_s": round(total_t, 2),
                                 "peak_vram_gb": model.peak_vram_gb()}
    return result


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", help="identifiant Hugging Face du modele")
    ap.add_argument("--tag", required=True, help="nom court de l'experience (ex. qwen2.5-3b_fp16)")
    ap.add_argument("--mock", action="store_true", help="faux modele, sans GPU (test du script)")
    ap.add_argument("--data-dir", type=Path, default=HERE / "data")
    ap.add_argument("--out-dir", type=Path, default=HERE.parent / "results")
    ap.add_argument("--alert-files", nargs="+", default=DEFAULT_ALERT_FILES)
    ap.add_argument("--batch-sizes", nargs="+", type=int, default=[1, 4, 8])
    ap.add_argument("--no-throughput", action="store_true", help="ne pas mesurer le debit en batch")
    ap.add_argument("--limit", type=int, default=None, help="ne tester que les N premiers exemples")
    args = ap.parse_args()
    if not args.mock and not args.model:
        ap.error("--model est obligatoire (sauf avec --mock)")

    qa = load_jsonl(args.data_dir / "qa_cyber.jsonl")
    alert_sets = {}
    for fname in args.alert_files:
        path = args.data_dir / fname
        if path.exists():
            alert_sets[path.stem] = load_alerts(path)
        else:
            print(f"[!] fichier absent, ignore : {path}")
    validate(qa, alert_sets)
    valid_ids = load_valid_mitre(args.data_dir / "mitre_attack_ids.txt")
    if args.limit:
        qa = qa[:args.limit]
        alert_sets = {k: v[:args.limit] for k, v in alert_sets.items()}

    model = MockModel() if args.mock else HFModel(args.model)
    all_preds = []
    print(f"== QCM ({len(qa)} questions)")
    mcq_sum, preds = run_mcq(model, qa)
    all_preds += preds
    alerts_sum = {}
    for name, alerts in alert_sets.items():
        print(f"== {name} ({len(alerts)} alertes)")
        alerts_sum[name], preds = run_alerts(model, name, alerts, valid_ids)
        all_preds += preds
    peak_single = model.peak_vram_gb()

    throughput = {}
    if not args.no_throughput:
        all_alerts = [r["alert"] for a in alert_sets.values() for r in a]
        step = max(1, len(all_alerts) // 16)
        prompts = [alert_prompt(t) for t in all_alerts[::step][:16]]
        print(f"== Debit en batch ({len(prompts)} prompts, tailles {args.batch_sizes})")
        throughput = run_throughput(model, prompts, args.batch_sizes)

    result = {"tag": args.tag, "model": "mock" if args.mock else args.model,
              "date": datetime.now().isoformat(timespec="seconds"),
              "prompt_version": PROMPT_VERSION, "gpu": model.gpu,
              "load_time_s": model.load_time_s, "vram_after_load_gb": model.vram_after_load_gb,
              "peak_vram_gb": peak_single,
              "mcq": mcq_sum, "alerts": alerts_sum, "throughput": throughput}
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with open(args.out_dir / f"benchmark_{args.tag}.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    with open(args.out_dir / f"benchmark_{args.tag}_predictions.jsonl", "w", encoding="utf-8") as f:
        for p in all_preds:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    print(f"\nModele : {result['model']} | GPU : {model.gpu} | chargement {model.load_time_s} s"
          f" | VRAM apres chargement {model.vram_after_load_gb} Go | VRAM pic {peak_single} Go")
    print(f"QCM : accuracy = {mcq_sum['accuracy']:.1%} (IC95 {mcq_sum['accuracy_ci95']})"
          f" | latence moy. {mcq_sum['latency']['mean_s']} s")
    for name, s in alerts_sum.items():
        print(f"{name} : categorie acc = {s['category_accuracy']:.1%} | macro-F1 = {s['category_macro_f1']:.3f}"
              f" | severite = {s['severity_accuracy']:.1%} | MITRE = {s['mitre_accuracy']:.1%}")
        print(f"   hallucination = {s['hallucination_rate']:.1%} (MITRE inexistant {s['invalid_mitre_rate']:.1%},"
              f" entites inventees {s['unsupported_entity_rate']:.1%}) | format invalide = {s['invalid_format_rate']:.1%}"
              f" | latence moy. {s['latency']['mean_s']} s | {s['latency']['mean_tokens_per_s']} tokens/s")
    for b, t in throughput.items():
        print(f"debit {b} : {t['tokens_per_s']} tokens/s, {t['samples_per_s']} alertes/s, VRAM pic {t['peak_vram_gb']} Go")
    print(f"Resultats ecrits dans {args.out_dir / ('benchmark_' + args.tag + '.json')}")


if __name__ == "__main__":
    main()
