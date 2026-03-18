import csv
import random

# Columns matching expected format
COLUMNS = [
    "length", "n_ns", "n_vowels", "life_time", "n_vowel_chars",
    "n_constant_chars", "n_nums", "n_other_chars", "entropy",
    "n_mx", "ns_similarity", "n_countries", "n_labels", "label"
]

def generate_benign():
    length = random.randint(8, 15)
    n_ns = random.randint(2, 6)
    n_vowels = random.randint(2, 5)
    life_time = random.randint(2001, 5000)
    n_vowel_chars = random.randint(2, 6)
    n_constant_chars = random.randint(4, 10)
    n_nums = random.randint(0, 2)
    n_other_chars = 0
    entropy = random.uniform(2.5, 3.5)
    n_mx = random.randint(1, 4)
    ns_similarity = random.uniform(0.9, 1.0)
    n_countries = random.randint(1, 2)
    n_labels = random.randint(201, 1000)
    label = 0
    return [length, n_ns, n_vowels, life_time, n_vowel_chars, n_constant_chars, n_nums, n_other_chars, entropy, n_mx, ns_similarity, n_countries, n_labels, label]

def generate_malicious():
    length = random.randint(15, 30)
    n_ns = random.randint(0, 2)
    n_vowels = random.randint(1, 3)
    life_time = random.randint(0, 365)
    n_vowel_chars = random.randint(1, 4)
    n_constant_chars = random.randint(8, 20)
    n_nums = random.randint(2, 10)
    n_other_chars = random.randint(0, 5)
    entropy = random.uniform(3.5, 5.0)
    n_mx = random.randint(0, 1)
    ns_similarity = random.uniform(0.0, 0.5)
    n_countries = random.randint(2, 10)
    n_labels = random.randint(0, 50)
    label = 1
    return [length, n_ns, n_vowels, life_time, n_vowel_chars, n_constant_chars, n_nums, n_other_chars, entropy, n_mx, ns_similarity, n_countries, n_labels, label]

def main():
    with open('test_eval_data.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(COLUMNS)
        
        # 50 Benign
        for _ in range(50):
            writer.writerow(generate_benign())
            
        # 50 Malicious
        for _ in range(50):
            writer.writerow(generate_malicious())
            
    print("Generated test_eval_data.csv with 100 samples.")

if __name__ == "__main__":
    main()
