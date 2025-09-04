# Version Analysis Script

This script analyzes version inconsistencies between different vulnerability databases and classifies them into five categories:

1. **Equal**: The vulnerability has equal affected versions in both databases
2. **Disjoint**: The vulnerability has disjoint affected versions in both databases
3. **Contain**: The affected versions in DB1 contain the affected versions in DB2
4. **Contained**: The affected versions in DB2 contain the affected versions in DB1
5. **Overlap**: The vulnerability has overlapping affected versions in both databases

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Set up your OpenAI API key in the script (already configured in the code)

## Usage

Run the script:
```bash
python RQ1.py
```

The script will:
1. Read the input file `pair_wise_versions.json`
2. Process each CVE entry and compare version ranges
3. Save progress in a checkpoint file
4. Generate the final output

## Features

- Checkpoint system for resuming interrupted processing
- LLM-assisted analysis for complex version ranges
- Progress bar showing processing status
- Error handling and logging
- Automatic version normalization 