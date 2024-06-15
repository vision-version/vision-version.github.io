# VERJava

[VERJava](https://ieeexplore.ieee.org/document/9978189) is a tool for evaluating target vulnerable versions in open-source Java software.
This is the replication package for the paper titled "VERJava: Vulnerable Version Identification for Java OSS with a Two-Stage Analysis".
# Usage

## Setup

```bash
pip install requirements.txt
```

## Git Code Repo

VERJava supports 2 modes: one is Git Code Repo, and the other is Java Jar File.

```bash
python main.py -m code -r <repo_path> -c <patch_commit_id>
```

## Java Jar File

```bash
python main.py -m jar -r <repo_path> -c <patch_commit_id> --jar <jars_path>
```
