import asyncio
import aiohttp
import argparse
import csv
import time
import sys
import os
from typing import List, Dict, Any, Optional, Set
from tqdm.asyncio import tqdm
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, recall_score
import numpy as np

# Label Normalization
def normalize_label(label: Any) -> Optional[int]:
    label_str = str(label).strip().lower()
    if label_str in ["benign", "0", "good"]:
        return 0
    if label_str in ["malicious", "phishing", "1", "bad"]:
        return 1
    return None

def inspect_csv(file_path: str):
    """Prints the first 5 rows and unique label values from the CSV."""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return

    print(f"\n--- Inspecting {file_path} ---")
    labels: Set[str] = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            print("Header:", reader.fieldnames)
            print("\nFirst 5 rows:")
            for i, row in enumerate(reader):
                if i < 5:
                    print(f"Row {i+1}: {row}")
                labels.add(row.get("label", "MISSING"))
                # Don't read the whole 600MB file just for unique labels if it's too big,
                # but for 600MB it's okay to read if we just want unique labels.
                # Actually, let's limit it to first 1000 rows for unique labels during inspection to be safe.
                if i >= 1000:
                    print("... (Inspected first 1000 rows for labels)")
                    break
            
            print(f"\nUnique labels found (in first 1000 rows): {labels}")
            
            # Check for required columns
            if reader.fieldnames:
                if "url" not in reader.fieldnames:
                    print("⚠️  Warning: 'url' column not found!")
                if "label" not in reader.fieldnames:
                    print("⚠️  Warning: 'label' column not found!")
    except Exception as e:
        print(f"Error during inspection: {e}")
    print("----------------------------\n")

async def evaluate_url(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, base_url: str, url: str, true_label: int, timeout: int) -> Dict[str, Any]:
    async with semaphore:
        try:
            async with session.post(
                f"{base_url.rstrip('/')}/test_url",
                json={"url": url},
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status != 200:
                    return {"url": url, "true": true_label, "pred": None, "status": f"HTTP {resp.status}"}
                data = await resp.json()
                return {
                    "url": url,
                    "true": true_label,
                    "pred": data.get("mal_status"),
                    "source": data.get("source", "model"),
                    "inference_time_ms": data.get("inference_time_ms", 0),
                    "status": "ok"
                }
        except asyncio.TimeoutError:
            return {"url": url, "true": true_label, "pred": None, "status": "timeout"}
        except Exception as e:
            return {"url": url, "true": true_label, "pred": None, "status": f"error: {e}"}

def print_report(results: List[Dict[str, Any]], dataset_name: str, wall_time: float):
    completed = [r for r in results if r["status"] == "ok" and r["pred"] is not None]
    timed_out = [r for r in results if r["status"] == "timeout"]
    errored = [r for r in results if r["status"] != "ok" and r["status"] != "timeout"]

    total = len(results)
    n_completed = len(completed)
    n_timed_out = len(timed_out)
    n_errored = len(errored)

    if n_completed == 0:
        print("\nNo URLs were successfully evaluated. Check your backend and dataset.")
        return

    y_true = [r["true"] for r in completed]
    y_pred = [r["pred"] for r in completed]

    # Metrics
    acc = accuracy_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

    # Target comparison
    def get_status_icon(val, target):
        return "✅" if val >= target else "⚠️"

    print("╔" + "═" * 46 + "╗")
    print("║     DOMYNTRIX-AI LIVE EVALUATION REPORT      ║")
    print("╠" + "═" * 46 + "╣")
    print(f"║  Dataset:      {os.path.basename(dataset_name):<29} ║")
    print(f"║  Total URLs:   {total:<29} ║")
    print(f"║  Completed:    {n_completed:<3}  ({(n_completed/total*100):.1f}%)                  ║")
    print(f"║  Timed Out:    {n_timed_out:<3}  ({(n_timed_out/total*100):.1f}%)  ← stale domains  ║")
    print(f"║  Errors:       {n_errored:<3}  ({(n_errored/total*100):.1f}%)                   ║")
    
    n_benign = y_true.count(0)
    n_mal = y_true.count(1)
    print(f"║  Evaluated:    {n_completed:<3}  (benign: {n_benign} / mal: {n_mal}) ║")
    print("╠" + "═" * 46 + "╣")
    print("║  METRIC        YOURS     PAPER TARGET        ║")
    print(f"║  Accuracy      {acc*100:>5.1f}%     94.0%    {get_status_icon(acc, 0.94)}          ║")
    print(f"║  F1-Score      {f1:>6.3f}     0.920    {get_status_icon(f1, 0.92)}          ║")
    print(f"║  Precision     {prec:>6.3f}     0.960    {get_status_icon(prec, 0.96)}          ║")
    print(f"║  Recall        {rec:>6.3f}     0.900    {get_status_icon(rec, 0.90)}          ║")
    print("╠" + "═" * 46 + "╣")
    print("║  CONFUSION MATRIX                            ║")
    print("║             Pred 0    Pred 1                 ║")
    print(f"║  Actual 0    {cm[0][0]:<10} {cm[0][1]:<10}           ║")
    print(f"║  Actual 1    {cm[1][0]:<10} {cm[1][1]:<10}           ║")
    print("╠" + "═" * 46 + "╣")
    
    whitelist_hits = len([r for r in completed if r["source"] == "whitelist"])
    model_hits = len([r for r in completed if r["source"] != "whitelist"])
    # Filter out 0 ms inference times which might be cached or error cases
    inf_times = [r["inference_time_ms"] for r in completed if r["source"] != "whitelist" and r["inference_time_ms"] > 0]
    avg_inf = np.mean(inf_times) if inf_times else 0
    
    print("║  SOURCE BREAKDOWN                            ║")
    print(f"║  Whitelist hits:  {whitelist_hits:<3}  ({(whitelist_hits/n_completed*100):.1f}%)               ║")
    print(f"║  Model evaluated: {model_hits:<3}  ({(model_hits/n_completed*100):.1f}%)               ║")
    print(f"║  Avg inference:   {int(avg_inf):<4} ms (model only)       ║")
    print("╚" + "═" * 46 + "╝")

    print("\nFull Classification Report:")
    print(classification_report(y_true, y_pred, target_names=["benign", "malicious"], zero_division=0))

    if total > 0 and (n_timed_out / total) > 0.1:
        print("\n\n⚠️  High timeout rate (>10%) — many 2020 domains are likely defunct. Results may underestimate true model performance.")
    
    print(f"\nTotal wall-clock time: {wall_time:.2f} seconds")

async def main():
    parser = argparse.ArgumentParser(description="Evaluate live Domyntrix-AI backend API")
    parser.add_argument("--data", required=True, help="Path to Mendeley CSV")
    parser.add_argument("--url", default="http://127.0.0.1:5000", help="Backend base URL")
    parser.add_argument("--concurrency", type=int, default=10, help="Max simultaneous requests")
    parser.add_argument("--limit", type=int, help="Optional cap on rows to evaluate")
    parser.add_argument("--timeout", type=int, default=15, help="Per-request timeout")
    parser.add_argument("--inspect", action="store_true", help="Inspect the first 5 rows and labels of the CSV")
    args = parser.parse_args()

    if args.inspect:
        inspect_csv(args.data)
        return

    # Load data
    rows = []
    print(f"Loading data from {args.data}...")
    try:
        with open(args.data, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get("url", "")
                if url:
                    url = url.strip()
                
                label = normalize_label(row.get("label"))
                
                if not url or label is None:
                    continue
                
                rows.append((url, label))
                if args.limit and len(rows) >= args.limit:
                    break
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    if not rows:
        print("No valid rows found in CSV. Check column names ('url', 'label') and content.")
        sys.exit(0)

    print(f"Starting evaluation of {len(rows)} URLs...")
    start_time = time.time()
    
    semaphore = asyncio.Semaphore(args.concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [
            evaluate_url(session, semaphore, args.url, url, label, args.timeout)
            for url, label in rows
        ]
        # tqdm.asyncio.tqdm works with gather
        results = await tqdm.gather(*tasks, desc="Evaluating URLs")

    wall_time = time.time() - start_time

    # Print Report
    print_report(results, args.data, wall_time)

    # Save Results
    output_file = "evaluation_results.csv"
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "true_label", "predicted_label", "source", "inference_time_ms", "status"])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "url": r["url"],
                    "true_label": r["true"],
                    "predicted_label": r.get("pred"),
                    "source": r.get("source", ""),
                    "inference_time_ms": r.get("inference_time_ms", 0),
                    "status": r["status"]
                })
        print(f"\nDetailed results saved to {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")

if __name__ == "__main__":
    asyncio.run(main())
