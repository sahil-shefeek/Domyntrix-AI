# MADONNA

> **M**alicious **A**nd **D**angerous **O**nline **N**etwork **N**ame **A**nalysis

Browser-Based Malicious Domain Detection through Optimized Neural Network with Feature Analysis

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![Chrome Extension](https://img.shields.io/badge/chrome-extension-orange.svg)](https://developer.chrome.com/docs/extensions/)

---

## 📖 About

MADONNA is a real-time malicious domain detection system that combines a Chrome browser extension with a neural network-powered backend API. It analyzes domain features to identify potentially harmful websites before users interact with them.

The full paper was presented at the **38th IFIP TC 11 International Conference on Information Security and Privacy Protection (IFIPSec) - 2023**.

### 📚 Citation

If you use this plugin or model in your research, please cite:

> Senanayake, J., Rajapaksha, S., Yanai, N., Komiya, C., Kalutarage, H. (2024). *MADONNA: Browser-Based MAlicious Domain Detection Through Optimized Neural Network with Feature Analysis*. In: Meyer, N., Grocholewska-Czuryło, A. (eds) ICT Systems Security and Privacy Protection. SEC 2023. IFIP Advances in Information and Communication Technology, vol 679. Springer, Cham. https://doi.org/10.1007/978-3-031-56326-3_20

---

## 🚀 Getting Started

### Prerequisites

- Python 3.12 or higher
- [uv](https://docs.astral.sh/uv/) - Fast Python package manager
- Google Chrome browser

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd MADONNA
   ```

2. **Install dependencies:**
   ```bash
   uv sync
   ```

3. **Start the API server:**
   ```bash
   uv run python main.py
   ```
   The server will start at `http://127.0.0.1:5000/`

4. **Load the Chrome extension:**
   - Navigate to `chrome://extensions/`
   - Enable **Developer mode** (toggle in top-right)
   - Click **Load unpacked**
   - Select the `extension/` folder inside the project

---

## 🔌 Usage

1. Ensure the Flask API server is running
2. Click the MADONNA extension icon in Chrome
3. The extension will automatically analyze the current tab's domain
4. View the result:
   - 🟢 **Safe** - Domain appears legitimate
   - 🔴 **Threat Detected** - Domain appears malicious

---

## 🏗️ Architecture

```
┌─────────────────────┐      HTTP       ┌─────────────────────┐
│  Chrome Extension   │ ──────────────► │    Flask API        │
│  (Browser Popup)    │                 │  (localhost:5000)   │
└─────────────────────┘                 └──────────┬──────────┘
                                                   │
                                                   ▼
                                        ┌─────────────────────┐
                                        │  Feature Extraction │
                                        │  (Domain Analysis)  │
                                        └──────────┬──────────┘
                                                   │
                                                   ▼
                                        ┌─────────────────────┐
                                        │   TFLite Model      │
                                        │ (Neural Network)    │
                                        └─────────────────────┘
```

### Project Structure

```
MADONNA/
├── main.py                 # Flask API server
├── feature_extractions.py  # Domain feature extraction
├── model_prediction.py     # ML model utilities
├── lite_model_optimized_float16.tflite  # Optimized neural network
├── GeoLite2-City.mmdb      # GeoIP database
├── pyproject.toml          # Python dependencies (uv)
├── requirements.txt        # Legacy pip requirements
└── extension/              # Chrome extension
    ├── manifest.json       # Extension manifest (v3)
    ├── index.html          # Popup UI
    └── script.js           # Extension logic
```

---

## 🔍 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check - returns `{"Malicious_status": "Yes"}` |
| `/test_url/<url>` | GET | Analyze a URL for malicious activity |

**Note:** When passing URLs to `/test_url/`, replace all `/` characters with `_**_`

**Example:**
```bash
curl http://127.0.0.1:5000/test_url/example.com_**_path_**_page
```

**Response:**
```json
{"mal_status": 0}  // 0 = benign, 1 = malicious
```

---

## 🧠 How It Works

### Feature Selection

The model analyzes multiple domain features to detect malicious patterns:

![Feature Selection](https://user-images.githubusercontent.com/102326773/223765132-1461c601-8e0d-475d-b876-de6a20a12971.png)

### System Overview

![MADONNA Overview](https://user-images.githubusercontent.com/102326773/223764566-a9df38e2-2cf3-4f46-aba4-fc93178e9226.png)

---

## 📊 Evaluation Results

<details>
<summary><strong>Click to expand evaluation details</strong></summary>

### Accurate Benign Classifications (True Negatives)
![TN](https://user-images.githubusercontent.com/102326773/223765795-35827e36-2ca7-44d1-ac71-a2d04fdf3121.png)

### Inaccurate Benign Classifications (False Negatives)
![FN](https://user-images.githubusercontent.com/102326773/223765884-dabf8d6e-babc-4c05-a1c9-4127cae70e9b.png)

### Accurate Malicious Classifications (True Positives)
![TP](https://user-images.githubusercontent.com/102326773/223765993-b164cca3-321a-461b-99d8-cc29e2bbe622.png)

### Inaccurate Malicious Classifications (False Positives)
![FP](https://user-images.githubusercontent.com/102326773/223766085-65df10a0-13de-4e3a-8665-436f2c144377.png)

### Feature Values Distribution - False Negatives
![Feature Distribution FN](https://user-images.githubusercontent.com/102326773/223766391-0f826ba2-1cd1-431f-a64d-6c5d618133c1.png)

### Feature Values Distribution - False Positives
![Feature Distribution FP](https://user-images.githubusercontent.com/102326773/223766472-6923325a-985c-44e3-926d-4b58eb916347.png)

</details>

---

## 🛠️ Development

### Running in Development

```bash
# Install dependencies
uv sync

# Run the server
uv run python main.py

# Or with auto-reload (install flask[async] if needed)
uv run flask --app main run --debug
```

### Adding New Dependencies

```bash
uv add <package-name>
```

---

## 📄 License

This project is licensed under the terms specified in [LICENSE.txt](LICENSE.txt).

---

## 👥 Authors

- RGU-OU Research Team

## 🙏 Acknowledgments

- GeoLite2 database by MaxMind
- TensorFlow Lite for model optimization





# honors-project
