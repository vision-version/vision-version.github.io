# Version Inconsistency Analysis

Scripts for analyzing version inconsistencies between vulnerability databases and generating LaTeX tables.

## Scripts

### `analysis.py`
Processes version analysis results and categorizes inconsistencies into five types:
- **Equal**: Equal affected versions
- **Disjoint**: Disjoint affected versions  
- **Contain**: DB1 contains DB2's versions
- **Contained**: DB2 contains DB1's versions
- **Overlap**: Overlapping affected versions

### `latex.py`
Converts analysis results into LaTeX table format for academic papers.

## Usage

```bash
python analysis.py    # Generate inconsistency_results.json
python latex.py       # Output LaTeX table rows
```

## Database Mapping
- `cve` → VDA, `github` → VDB, `gitlab` → VDC, `veracode` → VDD, `snyk` → VDE
