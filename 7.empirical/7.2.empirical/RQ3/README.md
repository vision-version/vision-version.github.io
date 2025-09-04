# Ecosystem Analysis and Metrics

Scripts for analyzing vulnerability detection performance across programming ecosystems and calculating precision, recall, and F1 metrics.

## Scripts

### `calculate_metrics.py`
Calculates precision, recall, and F1 metrics across ecosystems:
- Ecosystem-level averages (Python, JavaScript, Java, PHP, C/C++)
- Source-specific metrics breakdown
- Filters problematic CVEs for cleaner analysis

### `cve_num.py`
Analyzes CVE distribution across programming ecosystems and calculates coverage percentages.

### `get_tags/`
Version tag analysis and precision/recall calculation scripts.

### `c/` and `java/`
Ecosystem-specific analysis results for C/C++ and Java.

## Usage

```bash
python calculate_metrics.py  # Calculate ecosystem metrics
python cve_num.py           # Analyze CVE distribution
```

## Ecosystems Covered
- **C/C++**: Unmanaged C/C++ vulnerabilities
- **Java**: Maven-based Java vulnerabilities  
- **Python**: Python package vulnerabilities
- **JavaScript**: npm-based JavaScript vulnerabilities
- **PHP**: PHP application vulnerabilities
