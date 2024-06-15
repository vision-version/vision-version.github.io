# vuddy
VUDDY is an approach for scalable and accurate vulnerable code clone detection. Principles and results are discussed in
[VUDDY: A Scalable Approach for Vulnerable Code Clone Discover](https://ccs.korea.ac.kr/pds/SNP17.pdf), which was published in 38th
IEEE Symposium on Security and Privacy (S&P'17).

We reproduced the Java version of this tool as our baseline.

## How to use
### Requirements

* ***Linux***: vuddy is designed to work on any of the operating systems. However, currently, this repository only focuses on the Linux environment.
* ***Git***
* ***Python 3***
* ***[tree-sitter](https://tree-sitter.github.io/tree-sitter/)***: for function hashing.

Our utilized versions: Python 3.12.3 and some other elevant dependent packages listed in [requirements.txt](./requirements.txt) on Ubuntu 18.04.

To setup, just run:
```
pip install -r requirements.txt
```

### Running vuddy

※ If you have problems related to path information, try testing with absolute paths.

### Signature generation

#### 1. Restore functions before/after patch
 - store the patch for the CVE that needs to be determined [diff_java](./diff_java), the path need to be the format as "CVE/CVE.txt". Clone the relevant repositories into the a diretory and Specify the directory paths in [config.py](./config.py)(line 3). The CVE patches involved in this experiment are stored in [diff_java](./diff_java), and you only need to clone the repositories listed in [CLONE_SAMPLE](./CLONE_SAMPLE).
 - Execute [get_source_from_cvepatch.py](./get_source_from_cvepatch.py) to restores the **pre-patch and post-patch functions from the collected CVE vulnerability patches, respectively**. The restored functions are stored under [vul_java/CVE_ID](./vul_java). The function before the vulnerability patch is saved as *_OLD.vul as a vulnerable function, and the function after the patch is saved as *_NEW.vul as a safe function.
 In the arguments, CVE-ID refers to the CVE-ID you need to generate the signature, and the REPONAME refers to the repository name.

 ```
 python get_source_from_cvepatch.py CVE-ID REPONAME
 ```
#### 2. Remove duplicate vulnerable sources
 - Execute [vul_dup_remover.py](./vul_dup_remover.py), among all vulnerable functions stored under [vul_java](./vul_java)/, all but one duplicate file was removed.
 ```
 python vul_dup_remover.py
 ```
#### 3. Bulk removal of false positive cases
 - Execute [vul_verifier.py](./vul_verifier.py)
 Cases that cause false positives when detecting code clones are collectively removed from this module. Currently, two removal rules are applied, and rules can be added/removed arbitrarily according to policy. Rule 1) Delete if the abstraction results of the old function and new function are the same. Rule 2) Delete if the function header changes and it is impossible to identify the relationship before/after the patch. 
 ```
 python vul_verifier.py
 ```

#### 4. Generate hash index file of vulnerable sources
 - Execute [vul_hidx_generator.py](./vul_hidx_generator.py) to generate hash indices of residual functions. The created hash index has the extension *.hidx and is stored under [signature_java](./signature_java). At this time, two types of indexes can be created depending on the purpose: 
  If –a 0 is used as an argument, an index is created for exactmatching. 
  If –a 4 is used as an argument, an index is created for abstractmatching.
  The CVE-ID refers to the CVE-ID you need to generate the signature.
 ```
 python vul_hidx_generator.py -a 0/4 CVE-ID
 ```

### Detection

#### 1. Generate the signature of the target repo
 - Specify the directory paths in [config.py](./config.py) (line 4); these should be matched the path of decompiled jar that you want to detect.
 - Execute [get_hash_target_repo.py](./get_hash_target_repo.py) to generate hash indices of each functions in the decompiled jar.The created hash index has the extension *.hidx and is stored under [targetRepo_java](./targetRepo_java). At this time, two types of indexes can be created depending on the purpose: 
   If –a 0 is used as an argument, an index is created for exactmatching. 
  If –a 4 is used as an argument, an index is created for abstractmatching.
  The jar_name refers to the name of the decompiled jar directory it stored.
 ```
 python get_hash_target_repo.py -a 0/4 decompiled_jar
 ```
#### 2. evaluate target vulnerable versions in open-source Java software
  - Execute [detect_opt.py](./detect_opt.py) (several warnings may occur due to encoding issues), the result will be shown in [results_Java_tree.txt](./results_Java_tree.txt)
  
The results of our experientment is shown in [results_Java_tree.txt](./results_Java_tree.txt)