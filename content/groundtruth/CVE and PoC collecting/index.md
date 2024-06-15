---
title: CVE and PoC collecting
# summary: Easily learn JavaScript in 10 minutes!
date: 2024-06-13
type: docs
math: false
# tags:
#   - JavaScript
image:
  caption: 'Embed rich media such as videos and LaTeX math'
---
## Collecting Vulnerabilities

- Collecting Vulnerabilities. We collected CVEs with their patch (e.g., GitHub commits) in their references from January 1999 to May 2024 from NVD. It covered existing datasets of V-SZZ and VerJava. We obtained [1,083 CVEs with its patch](https://github.com/vision-version/vision-version.github.io/blob/main/Vision/1.groundtruth/PatchCollect.json). 


## Collecting Test Cases/Proof-of-Concepts and Creating Test Cases

- Collecting Test Cases/Proof-of-Concepts and Creating Test Cases. We manually inspected test cases included in the patches. If not present, we searched for patch commits in GitHub repositories using CVE IDs and websites containing vulnerability “exploits” or “proof-of-concepts (PoCs)”. We analyzed their triggering logic and transformed them into JUnit test cases. [We obtained 102 CVEs with test cases](https://github.com/vision-version/vision-version.github.io/tree/main/Vision/1.groundtruth/testcase-trigger/testcase-trigger), each with an assertion of the trigger status.
