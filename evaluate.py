import argparse
import csv
import os
import sys
import time
import numpy as np
import tensorflow as tf
from tqdm import tqdm
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
    classification_report,
)

# Paper target constants from Table 6
PAPER_TARGETS = {
    "accuracy": 0.940,
    "f1": 0.920,
    "precision": 0.960,
    "recall": 0.900,
}

EXPECTED_COLUMNS = [
    "length", "n_ns", "n_vowels", "life_time", "n_vowel_chars",
    "n_constant_chars", "n_nums", "n_other_chars", "entropy",
    "n_mx", "ns_similarity", "n_countries", "n_labels", "label"
]

def validate_csv(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            print(f"Error: CSV file is empty: {file_path}")
            sys.exit(1)
            
        if header != EXPECTED_COLUMNS:
            print("Error: CSV column mismatch.")
            print(f"Expected: {', '.join(EXPECTED_COLUMNS)}")
            print(f"Found:    {', '.join(header)}")
            sys.exit(1)

def get_comparison_symbol(value, target, is_accuracy=False):
    diff = abs(value - target)
    threshold_success = 0.005 if not is_accuracy else 0.005 # 0.5% for accuracy, 0.005 for others
    threshold_warning = 0.02
    
    if diff <= threshold_success:
        return "✅"
    elif diff <= threshold_warning:
        return "⚠️"
    else:
        return "❌"

def print_report(results, paper_targets, samples_info, timing_info, dataset_name, model_name):
    print("╔══════════════════════════════════════════════════════╗")
    print("║           DOMYNTRIX-AI EVALUATION REPORT             ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  Dataset:     {dataset_name:<38} ║")
    print(f"║  Samples:     {samples_info:<38} ║")
    print(f"║  Model:       {model_name:<38} ║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  METRIC          YOURS    PAPER TARGET               ║")
    
    metrics = [
        ("Accuracy", results['accuracy'], paper_targets['accuracy'], True),
        ("F1-Score", results['f1'], paper_targets['f1'], False),
        ("Precision", results['precision'], paper_targets['precision'], False),
        ("Recall", results['recall'], paper_targets['recall'], False),
    ]
    
    failed_significant = False
    for name, val, target, is_acc in metrics:
        symbol = get_comparison_symbol(val, target, is_acc)
        if symbol == "❌":
            failed_significant = True
        
        val_str = f"{val:.1%}" if is_acc else f"{val:.3f}"
        target_str = f"{target:.1%}" if is_acc else f"{target:.3f}"
        
        print(f"║  {name:<15} {val_str:<8} {target_str:<12} {symbol}      ║")
        
    print("╠══════════════════════════════════════════════════════╣")
    print("║  CONFUSION MATRIX                                    ║")
    cm = results['cm']
    print(f"║               Pred 0   Pred 1                        ║")
    print(f"║  Actual 0     {cm[0][0]:<8} {cm[0][1]:<8}                      ║")
    print(f"║  Actual 1     {cm[1][0]:<8} {cm[1][1]:<8}                      ║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  PERFORMANCE TIMING                                  ║")
    print(f"║  Total Time:   {timing_info['total']:.2f}s                                ║")
    print(f"║  Avg/Sample:   {timing_info['avg_us']:.2f}μs                              ║")
    print("╚══════════════════════════════════════════════════════╝")
    
    if failed_significant:
        print("\n[!] WARNING: Significant deviation (>2%) from paper targets detected.")
        print("Possible causes: Data mismatch, feature scaling differences, or model corruption.")

    print("\nDetailed Classification Report:")
    print(results['report'])

def main():
    parser = argparse.ArgumentParser(description="Domyntrix-AI Model Evaluation Harness")
    parser.add_argument("--data", type=str, help="Path to the labeled CSV dataset")
    parser.add_argument("--model", type=str, default="lite_model_optimized_float16.tflite", help="Path to the TFLite model")
    args = parser.parse_args()

    if not args.data:
        print("No dataset provided. To evaluate, download the MADONNA dataset from:")
        print("  http://www-infosec.ist.osaka-u.ac.jp/~yanai/dataset.pdf")
        print("Then run: uv run python evaluate.py --data path/to/features.csv")
        return

    validate_csv(args.data)

    # Load Model
    try:
        interpreter = tf.lite.Interpreter(model_path=args.model)
        interpreter.allocate_tensors()
        input_details = interpreter.get_input_details()
        output_details = interpreter.get_output_details()
    except Exception as e:
        print(f"Error loading TFLite model: {e}")
        sys.exit(1)

    # Data collections
    y_true = []
    y_pred = []
    
    # Read CSV
    with open(args.data, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    total_samples = len(rows)
    benign_count = sum(1 for r in rows if int(r['label']) == 0)
    malicious_count = total_samples - benign_count
    samples_info = f"{total_samples:,} ({benign_count:,}B / {malicious_count:,}M)"

    print(f"Starting inference on {total_samples} samples...")
    start_time = time.perf_counter()
    
    for row in tqdm(rows, desc="Evaluating"):
        # Prepare feature vector (all columns except 'label')
        features = [float(row[col]) for col in EXPECTED_COLUMNS[:-1]]
        X_test = np.array(features, dtype=np.float32)
        inp = np.expand_dims(X_test, axis=0)
        
        # Inference
        interpreter.set_tensor(input_details[0]['index'], inp)
        interpreter.invoke()
        pred_val = interpreter.get_tensor(output_details[0]['index'])[0][0]
        
        # Binary classification threshold 0.5
        prediction = 1 if pred_val >= 0.5 else 0
        
        y_true.append(int(row['label']))
        y_pred.append(prediction)
        
    end_time = time.perf_counter()
    total_time = end_time - start_time
    avg_us = (total_time / total_samples) * 1_000_000
    
    # Compute Metrics
    results = {
        'accuracy': accuracy_score(y_true, y_pred),
        'f1': f1_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred),
        'recall': recall_score(y_true, y_pred),
        'cm': confusion_matrix(y_true, y_pred),
        'report': classification_report(y_true, y_pred)
    }
    
    timing_info = {
        'total': total_time,
        'avg_us': avg_us
    }
    
    print_report(
        results, 
        PAPER_TARGETS, 
        samples_info, 
        timing_info, 
        os.path.basename(args.data), 
        os.path.basename(args.model)
    )

if __name__ == "__main__":
    main()
