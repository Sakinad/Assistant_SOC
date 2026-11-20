#!/usr/bin/env python3
"""Fine-tuning LoRA / QLoRA d'un SLM sur le dataset de triage d'alertes SOC (semaine 4).

QLoRA (--bits 4, par defaut) : le modele de base est charge en 4 bits (NF4) et gele ; seuls de
petits adaptateurs LoRA sont entraines. LoRA classique : --bits 16 (modele de base en FP16).
La perte n'est calculee que sur la reponse de l'assistant (pas sur le prompt).

Exemples (sur Colab, GPU T4) :
  python finetune_qlora.py --model Qwen/Qwen2.5-3B-Instruct --tag qwen2.5-3b_qlora --smoke
  python finetune_qlora.py --model Qwen/Qwen2.5-3B-Instruct --tag qwen2.5-3b_qlora \
         --output-dir /content/drive/MyDrive/cybersoc/adapters/qwen2.5-3b_qlora
  python finetune_qlora.py --model microsoft/Phi-3.5-mini-instruct --tag phi3.5-mini_qlora

Sorties :
  <output-dir>/adapter/          adaptateur LoRA (a NE PAS envoyer sur GitHub : trop volumineux)
  results/finetune_<tag>.json    resume de l'entrainement (courbes de perte, duree, VRAM, controle rapide)
"""
import argparse
import json
import random
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def build_example(tok, messages, max_len):
    """Tokenise une conversation ; seuls les tokens de la reponse de l'assistant ont un label."""
    prompt_text = tok.apply_chat_template(messages[:2], add_generation_prompt=True, tokenize=False)
    full_text = tok.apply_chat_template(messages, tokenize=False).rstrip("\n")
    assert full_text.startswith(prompt_text), "le gabarit de chat ne commence pas par le prompt"
    prompt_ids = tok(prompt_text, add_special_tokens=False)["input_ids"]
    full_ids = tok(full_text, add_special_tokens=False)["input_ids"]
    if full_ids[:len(prompt_ids)] != prompt_ids:  # frontiere de tokens differente : on concatene
        full_ids = prompt_ids + tok(full_text[len(prompt_text):], add_special_tokens=False)["input_ids"]
    full_ids = full_ids[:max_len]
    labels = ([-100] * len(prompt_ids) + full_ids[len(prompt_ids):])[:len(full_ids)]
    return {"input_ids": full_ids, "attention_mask": [1] * len(full_ids), "labels": labels}


def make_collator(pad_id):
    import torch

    def collate(batch):
        width = max(len(b["input_ids"]) for b in batch)
        pad = lambda seq, v: seq + [v] * (width - len(seq))
        return {"input_ids": torch.tensor([pad(b["input_ids"], pad_id) for b in batch]),
                "attention_mask": torch.tensor([pad(b["attention_mask"], 0) for b in batch]),
                "labels": torch.tensor([pad(b["labels"], -100) for b in batch])}
    return collate


def quick_check(model, tok, records, n, max_new_tokens=150):
    """Controle rapide sur n exemples de validation (generation reelle, decodage deterministe)."""
    import torch
    from evaluate import parse_alert
    model.eval()
    ok_cat = ok_fmt = 0
    shown = []
    for r in records[:n]:
        gold = json.loads(r["messages"][2]["content"])
        inputs = tok.apply_chat_template(r["messages"][:2], add_generation_prompt=True,
                                         return_tensors="pt", return_dict=True).to(model.device)
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
        text = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        p = parse_alert(text)
        ok_fmt += p["format_ok"]
        ok_cat += p["category"] == gold["category"]
        if len(shown) < 3:
            shown.append({"attendu": gold, "obtenu": text})
    return {"n": n, "json_valide": ok_fmt, "categorie_correcte": ok_cat, "exemples": shown}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="identifiant Hugging Face du modele de base")
    ap.add_argument("--tag", required=True, help="nom court de l'experience (ex. qwen2.5-3b_qlora)")
    ap.add_argument("--data-dir", type=Path, default=HERE / "data" / "finetune")
    ap.add_argument("--output-dir", type=Path, default=None, help="dossier de l'adaptateur (conseille : Google Drive)")
    ap.add_argument("--results-dir", type=Path, default=HERE.parent / "results")
    ap.add_argument("--bits", type=int, choices=[4, 16], default=4, help="4 = QLoRA, 16 = LoRA en FP16")
    ap.add_argument("--r", type=int, default=16, help="rang LoRA")
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--dropout", type=float, default=0.05)
    ap.add_argument("--epochs", type=float, default=3)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--batch-size", type=int, default=4)
    ap.add_argument("--grad-accum", type=int, default=4)
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--sanity", type=int, default=20, help="nb d'exemples de validation generes a la fin")
    ap.add_argument("--smoke", action="store_true", help="test rapide du pipeline : 8 etapes, 2 generations")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    if args.smoke:
        args.sanity = 2
    out_dir = args.output_dir or Path("/content/adapters") / args.tag

    import torch
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, Trainer,
                              TrainingArguments, set_seed)
    set_seed(args.seed)
    random.seed(args.seed)

    train_rec = load_jsonl(args.data_dir / "train.jsonl")
    val_rec = load_jsonl(args.data_dir / "val.jsonl")
    tok = AutoTokenizer.from_pretrained(args.model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    train_ds = [build_example(tok, r["messages"], args.max_len) for r in train_rec]
    val_ds = [build_example(tok, r["messages"], args.max_len) for r in val_rec]
    n_tok = [sum(l != -100 for l in e["labels"]) for e in train_ds]
    print(f"train {len(train_ds)} | val {len(val_ds)} | tokens a predire par exemple : moyenne "
          f"{sum(n_tok) / len(n_tok):.0f}, longueur max d'une sequence : {max(len(e['input_ids']) for e in train_ds)}")

    quant = None
    if args.bits == 4:
        quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                   bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16)
    model = AutoModelForCausalLM.from_pretrained(args.model, quantization_config=quant,
                                                 dtype=torch.float16, device_map={"": 0})
    model.config.use_cache = False
    if args.bits == 4:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    else:
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()
    lora = LoraConfig(r=args.r, lora_alpha=args.alpha, lora_dropout=args.dropout, bias="none",
                      target_modules="all-linear", task_type="CAUSAL_LM")
    model = get_peft_model(model, lora)
    for p in model.parameters():          # les poids entrainables doivent etre en FP32 (entrainement FP16)
        if p.requires_grad:
            p.data = p.data.float()
    model.print_trainable_parameters()
    torch.cuda.reset_peak_memory_stats()

    kwargs = dict(output_dir=str(out_dir), num_train_epochs=args.epochs,
                  per_device_train_batch_size=args.batch_size, per_device_eval_batch_size=args.batch_size,
                  gradient_accumulation_steps=args.grad_accum, learning_rate=args.lr,
                  lr_scheduler_type="cosine", warmup_steps=5, fp16=True, logging_steps=10,
                  save_strategy="epoch", save_total_limit=2, report_to="none", seed=args.seed,
                  optim="paged_adamw_8bit" if args.bits == 4 else "adamw_torch",
                  max_steps=8 if args.smoke else -1)
    try:
        targs = TrainingArguments(eval_strategy="epoch", **kwargs)
    except TypeError:                     # anciennes versions de transformers
        targs = TrainingArguments(evaluation_strategy="epoch", **kwargs)
    trainer = Trainer(model=model, args=targs, train_dataset=train_ds, eval_dataset=val_ds,
                      data_collator=make_collator(tok.pad_token_id))

    t0 = time.time()
    trainer.train()
    train_time = time.time() - t0
    peak_vram = round(torch.cuda.max_memory_allocated() / 1024 ** 3, 2)

    adapter_dir = out_dir / "adapter"
    trainer.save_model(str(adapter_dir))
    tok.save_pretrained(str(adapter_dir))

    model.config.use_cache = True
    check = quick_check(model, tok, val_rec, args.sanity)
    log = trainer.state.log_history
    summary = {"tag": args.tag, "model": args.model, "method": "QLoRA 4 bits (NF4)" if args.bits == 4 else "LoRA FP16",
               "lora": {"r": args.r, "alpha": args.alpha, "dropout": args.dropout, "target_modules": "all-linear"},
               "epochs": args.epochs, "lr": args.lr, "batch_size": args.batch_size, "grad_accum": args.grad_accum,
               "effective_batch": args.batch_size * args.grad_accum, "n_train": len(train_ds), "n_val": len(val_ds),
               "smoke_test": args.smoke, "train_time_min": round(train_time / 60, 1), "peak_vram_gb": peak_vram,
               "final_train_loss": next((l["loss"] for l in reversed(log) if "loss" in l), None),
               "eval_loss_by_epoch": [round(l["eval_loss"], 4) for l in log if "eval_loss" in l],
               "quick_check_on_val": check, "adapter_dir": str(adapter_dir), "log_history": log}
    args.results_dir.mkdir(parents=True, exist_ok=True)
    out_json = args.results_dir / f"finetune_{args.tag}.json"
    out_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nEntrainement termine en {summary['train_time_min']} min | VRAM pic {peak_vram} Go")
    print(f"Perte d'entrainement finale : {summary['final_train_loss']} | perte de validation par epoque : {summary['eval_loss_by_epoch']}")
    print(f"Controle rapide (validation) : JSON valide {check['json_valide']}/{check['n']}, "
          f"categorie correcte {check['categorie_correcte']}/{check['n']}")
    for ex in check["exemples"]:
        print("  attendu :", json.dumps(ex["attendu"], ensure_ascii=False))
        print("  obtenu  :", ex["obtenu"].strip())
    print(f"Adaptateur : {adapter_dir}\nResume : {out_json}")


if __name__ == "__main__":
    main()
