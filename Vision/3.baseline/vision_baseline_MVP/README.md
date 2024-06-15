# MVP
MVP is an approach for scalable and accurate vulnerable code clone detection. Principles are discussed in
[MVP: Detecting Vulnerabilities using Patch-Enhanced Vulnerability Signatures](https://chenbihuan.github.io/paper/sec20-xiao-mvp.pdf), which was published in 29th
Usenix Security Symposium (sec'20).

We reproduced the Java version of this tool as our baseline.

## How to use
### Requirements

* ***Linux***: vuddy is designed to work on any of the operating systems. However, currently, this repository only focuses on the Linux environment.
* ***Git***
* ***Python 3***
* ***[joern](https://docs.joern.io/installation)***
* ***[tree-sitter](https://tree-sitter.github.io/tree-sitter/)***: for function elemtents extraction.

Our utilized versions: Python 3.12.3, joern 1.1.1377 and some other elevant dependent packages listed in [requirements.txt](./requirements.txt) on Ubuntu 18.04.

To setup, just run:
```
pip install -r requirements.txt
```

### Running MVP

※ If you have problems related to path information, try testing with absolute paths.

### Signature generation


 - After install the joern, specify the directory paths of joern in [config.py](./config.py).
 - Store the patch for the CVE that needs to be determined [CVEcommit](./CVEcommit), the path need to be the format as "CVE.txt". Clone the relevant repositories into the a diretory and record the related information which include **the CVE-ID corresponding to the patch file, the absolute path to the file storing GitHub commit content, the absolute path to the directory of the GitHub repository corresponding to the CVE and the absolute path to the directory of joern-cli** into the [CVEdataset.csv](./CVEdataset.csv) 
 The CVE patches involved in this experiment are stored in [CVEcommit](./CVEcommit), and you only need to clone the repositories listed in [CLONE_SAMPLE](./CLONE_SAMPLE).
 - Execute [gen_fingerprint_multi.py](./gen_fingerprint_multi.py) to generate the signatures of the patch which you collected.

 ```
 python gen_fingerprint_multi.py
 ```
 - Extract the modified file into the [vulFileVersion](./vulFileVersion) and record the starting and ending lines of the patch modification function, as well as the file information in [sagaMulti.json](./infoFile/sagaMulti.json)

### Detection

 -  Record the related information which include **the absolute path of decompiled jar and the absolute path to the directory of joern-cli** into the [targetList.csv](./targetList.csv)
 - Execute [detect_multi.py](./detect_multi.py) to evaluate target vulnerable versions in open-source Java software, the result will be output to resultMultiSnippetVersion.txt.
 ```
 python detect_multi.py
 ```