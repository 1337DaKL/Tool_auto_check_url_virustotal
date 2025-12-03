# VirusTotal Multi-Threaded URL Scanner

A lightweight yet powerful multi-threaded tool for scanning large batches of URLs using the VirusTotal Public API.  
Designed for analysts who want speed, automation, and minimal hassle — the script handles splitting, threading, merging, and cleanup all by itself.

---

## Features

### Multi-threaded Scanning
- Automatically splits the URL list based on the number of API keys provided.
- Each API key runs in its own thread, dramatically increasing throughput.
- Fully automated — no manual configuration needed.

### URL Risk Classification
- Fetches `last_analysis_stats` directly from VirusTotal.
- Classifies URLs into:
  - **Malicious (≥ 3 detections)** → saved to `output.txt`
  - **Needs Review (< 3 detections)** → saved to `re.txt`

### Rate-Limit Friendly
- Built-in delay (`17s` between requests) reduces the chance of hitting `QuotaExceededError`.
- Safe for Public API usage.

### Automatic Merging & Cleanup
- Merges all temporary output files into final reports.
- Removes generated temporary files (`inputX.txt`, `outputX.txt`, `reX.txt`) after the scan.

---

## Installation

### Requirements
- Python **3.6+**

### Install Dependencies
```bash
py -m pip install vt-py


## Preparing the Input

Create an `input.txt` file in the same directory as the script:

```
http://example.com/malware1
http://clean-site.org
https://phishing.xyz
```

The script automatically ignores empty lines.

---

## Running the Tool

Run:

```bash
py script.py
```

API key formats:

- **Single key**
  ```
  KEY
  ```

- **Multiple keys (separated by dashes)**
  ```
  KEY1-KEY2-KEY3-KEY4
  ```

> Note: The sample code includes hardcoded keys for demonstration. Replace them with your own before use.

---

## Output Files

After scanning completes, the tool generates:

| File        | Description                                      |
|-------------|--------------------------------------------------|
| `output.txt` | URLs flagged as malicious (≥ 3 detections)       |
| `re.txt`     | URLs that appear safe or require manual review   |

---

## Workflow Overview

1. Load URLs from `input.txt`.
2. Split them into *N* parts based on the number of API keys.
3. Launch one scanning thread per key:
   - Each thread handles its subset of URLs.
   - Each writes to temporary output files.
4. Wait for all threads to finish.
5. Merge temporary results into:
   - `output.txt`
   - `re.txt`
6. Remove temporary files.
7. Done.

---

## 🛠️ Customization

### Malicious Detection Threshold

Inside `check_virustotal()`:

```python
if malicious < 3:
```

Change the number to tighten or loosen the detection rule.

### Request Delay

Inside `read_lines_from_txt()`:

```python
time.sleep(17)
```

- **Public API:** keep delay between **17–25 seconds**
- **Premium API:** can be reduced

---

## VirusTotal API Limits

| Limit       | Public API                 |
|-------------|----------------------------|
| Rate limit  | ~4 requests/minute         |
| Daily limit | ~500 requests/day          |

If exceeded:
- Wait **1 minute** → rate limit reset  
- Wait **24 hours** → daily limit reset  

---

## License

Released under the **MIT License**.
