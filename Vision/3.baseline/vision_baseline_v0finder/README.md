# V0Finder 
V0Finder is an approach for detecting correct origin information of public software vulnerabilities.
Its principles are discussed in [V0Finder: Discovering the Correct Origin of Publicly Reported Software Vulnerabilities](https://github.com/WOOSEUNGHOON/V0Finder-public/blob/main/paper/V0Finder_Security21.pdf), which will be published in 30th USENIX Security Symposium (Security 2021).

We reproduced the Java version of its step to find vulnerable clones as our baseline.

## How to use
### Requirements

#### Software
* ***Linux***: V0Finder is designed to work on any of the operating systems. However, currently, this repository only focuses on the Linux environment.
* ***Git***
* ***Python 3***
* ***[tree-sitter](https://tree-sitter.github.io/tree-sitter/)***: for function hashing.

Our utilized versions: Python 3.12.3 and some other elevant dependent packages listed in [requirements.txt](./requirements.txt) on Ubuntu 18.04.

To setup, just run:
```
pip install -r requirements.txt
```

#### Hardware
* We recommend a minimum of 32 GB RAM to utilize a large amount of OSS datasets in graph construction.
##

### Running V0Finder

※ If you have problems related to path information, try testing with absolute paths.

### Pool Construction (src/1_poolConstruction/)

#### 1. CVE Pool construction (src/1_poolConstruction/CVEPool)
 - Rewrite the patch for the CVE that needs to be determined in the format of the files in the [diff_commit directory](./src/1_poolConstruction/CVEPool/CVEcommit) and store them in the [diff_commit folder](./src/1_poolConstruction/CVEPool/CVEcommit). Clone the relevant repositories into the [clones directory](./src/1_poolConstruction/CVEPool/clones). The CVE patches involved in this experiment are stored in [diff_commit](./src/1_poolConstruction/CVEPool/CVEcommit), and you only need to clone the repositories listed in [CLONE_SAMPLE](./src1_poolConstruction/CVEPool/CLONE_SAMPLE).
 - Execute [CVEPatch_CollectorVersion.py](./src/1_poolConstruction/CVEPool/CVEPatch_Collector.py) (several warnings may occur due to encoding issues).
 ```
 python3 CVEPatch_CollectorVersion.py
 ```
 - Check the outputs (description based on the default paths).
   * ***./vulFuncs/***: Directory for storing extracted vulnerable functions (with code lines added/deleted from the corresponding patch) from all diffs;
   * ***./NVD_vulhashes***: The output file where the hash values of the vulnerable functions are stored.

#### 2. Software Pool construction (src/1_poolConstruction/SoftwarePool)
 - decompile the affected jar that you should detect.
 - Specify the directory paths in [OSS_CollectorVersion.py](./src/1_poolConstruction/SoftwarePool/OSS_Collector.py) (line 87), where decompiled jar and their functions will be stored
 - Execute [OSS_CollectorVersion.py](./src/1_poolConstruction/SoftwarePool/OSS_Collector.py) (several warnings may occur due to encoding issues).
 ```
 python3 OSS_CollectorVersion.py
 ```
 - Check the outputs (description based on the default paths).
   * ***./raw_functions/***: Directory for storing all extracted functions from all collected repositories;
   * ***./repo_functions/***: Directory for storing hashed extracted functions from all collected repositories.

### Graph Construction (src/2_graphConstruction/)

#### 1. Detecting vulnerable clones (src/2_graphConstruction/Step1_DetectingVulClones.py)
 - Specify the directory paths in [Step1_DetectingVulClones.py](./src/2_graphConstruction/Step1_DetectingVulClones.py) (line 9 to 12); these should be matched the output path of CVEPool and SoftwarePool.
 - Execute [Step1_DetectingVulClones.py](./src/2_graphConstruction/Step1_DetectingVulClones.py) (several warnings may occur due to encoding issues).
 ```
 python3 Step1_DetectingVulClones.py
 ```
 - Check the outputs (description based on the default paths).
   * ***./clone_detection_res***: A file that stores vulnerable clone detection results. The schema of each line in the file is as follow (delimited by tabs)
     * CVE ID
     * Vulnerable function hash value
     * Vulnerable function path in the OSS
     * Modification status
     * Vulnerable function information
     * Detected OSS
     * Version information

The results of our experientment is shown in [clone_detection_res](./src/2_graphConstruction/clone_detection_res)