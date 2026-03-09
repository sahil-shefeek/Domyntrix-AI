# Domyntrix AI

Browser-Based Malicious Domain Detection through Optimized Neural Network with Feature Analysis

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![Chrome Extension](https://img.shields.io/badge/chrome-extension-orange.svg)](https://developer.chrome.com/docs/extensions/)

---

## 📖 About

Domyntrix AI is a real-time malicious domain detection system that combines a Chrome browser extension with a neural network-powered backend API. It analyzes domain features to identify potentially harmful websites before users interact with them.

The full paper was presented at the **38th IFIP TC 11 International Conference on Information Security and Privacy Protection (IFIPSec) - 2023**.

### 📚 Citation

If you use this plugin or model in your research, please cite:

> Senanayake, J., Rajapaksha, S., Yanai, N., Komiya, C., Kalutarage, H. (2024). *MADONNA: Browser-Based MAlicious Domain Detection Through Optimized Neural Network with Feature Analysis*. In: Meyer, N., Grocholewska-Czuryło, A. (eds) ICT Systems Security and Privacy Protection. SEC 2023. IFIP Advances in Information and Communication Technology, vol 679. Springer, Cham. https://doi.org/10.1007/978-3-031-56326-3_20

---

## 🚀 Getting Started

This guide covers everything you need to set up the project locally on your machine. Choose the instructions for your specific operating system below.

### 1. Install Prerequisites

You will need **Git** and the **uv** package manager. 

<details open>
<summary><strong>Windows</strong></summary>

Open **PowerShell** as Administrator and run:
Install Git (if not already installed)
```powershell
winget install --id Git.Git -e --source winget
```
Install uv (Python package manager) (if not already installed)
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```
*Note: You may need to restart your terminal after installation.*
</details>

<details>
<summary><strong>Linux (Debian/Ubuntu)</strong></summary>

Open your terminal and run:
Update and install Git (if not already installed)
```bash
sudo apt update && sudo apt install -y git
```

Install uv (Python package manager)
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```
*Note: Restart your terminal or run `source $HOME/.local/bin/env` to apply changes.*
</details>

<details>
<summary><strong>🎩 Linux (Fedora)</strong></summary>

Open your terminal and run:
Install Git (if not already installed)
```bash
sudo dnf upgrade --refresh
sudo dnf install -y git
```
Install uv (Python package manager)
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```
*Note: Restart your terminal or run `source $HOME/.local/bin/env` to apply changes.*
</details>

<details>
<summary><strong>macOS</strong></summary>

Open your **Terminal** and run:
Install Homebrew (if not already installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install Git and uv using Homebrew
```bash
brew install git uv
```
</details>

### 2. Clone the Repository & Setup Project

Once the prerequisites are installed, open your terminal (or PowerShell on Windows) and run the following commands:

1. Clone the repository
```bash
git clone https://github.com/sahil-shefeek/Domyntrix-AI
cd Domyntrix-AI
```

2. Install dependencies using uv
```bash
uv sync
```

3. Apply database migrations
```bash
uv run alembic upgrade head
```

### 3. Run the API Server

You can run the API server locally on your machine or entirely inside a Docker container. Both options require [Docker](https://docs.docker.com/get-docker/) (or a compatible container runtime).

**Option A: Run Locally (Recommended for Development)**
Start Redis in detached mode
```bash
docker compose up redis -d
```

Start the FastAPI server natively
```bash
uv run python main.py
```
*The server will start at `http://127.0.0.1:5000/`*

**Option B: Run entirely via Docker**
Starts the API and Redis in detached mode
```bash
docker compose up --build -d
```

To shut down the containers later:
```bash
docker compose down
```

### 4. Load the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle switch in the top-right corner).
3. Click the **Load unpacked** button.
4. Select the `extension/` folder located inside your cloned `Domyntrix-AI` project directory.

---

## 🔌 Usage

1. Ensure your FastAPI server is running (Step 3 above).
2. Click the Domyntrix AI extension icon in your Chrome toolbar.
3. The extension will automatically extract features and analyze the current tab's domain.
4. View the result:
   - 🟢 **Safe** - Domain appears legitimate
   - 🔴 **Threat Detected** - Domain appears malicious

---

## 🏗️ Architecture

```
┌─────────────────────┐      HTTP       ┌─────────────────────┐
│  Chrome Extension   │ ──────────────► │    FastAPI          │
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
Domyntrix-AI/
├── main.py                 # FastAPI server
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

![Domyntrix AI Overview](https://user-images.githubusercontent.com/102326773/223764566-a9df38e2-2cf3-4f46-aba4-fc93178e9226.png)

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

Install dependencies
```bash
uv sync
```

Run database migrations
```bash
uv run alembic upgrade head
```

Run the server
```bash
uv run python main.py
```

Or with auto-reload (install fastapi[standard] if needed)
```bash
uv run uvicorn main:app --reload --port 5000
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
