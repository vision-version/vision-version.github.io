## prototype of Vision

### Dependency

- joern 2.1.0
- python 3.7
- treesitter 0.22.3
- [UniXcoder](https://github.com/microsoft/CodeBERT/tree/master/UniXcoder#2-similarity-between-code-and-nl)

### Set Up

    ```
    pip install requirements.txt
    ```

### Modules
- `joern`

    The core joern scala script, you should first install joern then put all scala script into the joern folder
    
    - `callsite.sc`: Identifies all call sites between two specified methods.
    - `methodcall.sc`: Searches for and lists all callers of a given method within the code.
    - `slice.sc`: Generates various slices of a program based on method and line number, including program dependency graphs (PDG) and specific statements like assignments and control structures.
    - `slice_per.sc`: Processes a JSON file to extract method signatures and line numbers for further analysis.
    - `slice_ver.sc`: Similar to `slice_per.sc`, this script processes versioned data from a JSON file, extracting method signatures and line numbers.
    - `normalize.sc`: Normalizes data for a given method and specific line number, including identifying local variables, parameters, and data types.
    - `search_method_in_file.sc`: Scans through files to find specific methods and their details.
    - `taint_analysis.sc`: Conducts taint analysis from specified source to sink within the code.

- `patch_callchain_generate`

    *related module of Vision: Critical Method Selection*
    
    entry script: CallChainGenerate.py

    run:

    ```
    python CallChainGenerate.py
    ```

- `patch_featuregraph_generate`

    *related module of Vision: Change Statement Slicing*

    entry script: GraphGenerate.py & JarGraphGenerate.py

    run:
    ```
    python GraphGenerate.py # for patch IPDG
    python JarGraphGenerate.py # for jar IPDG
    ```

- `taint_analysis`

    *related module of Vision: Critical Statement Selection*

    entry script: critical_node_locate.py, slice.py
    
    run:

    ```
    python critical_node_locate.py
    python slice.py
    ```

- `jar_statement_locate`

    *related module of Vision: Critical Method Mapping*

    *related module of Vision: Change Statement Mapping*

    entry script: mapping.py

    run:
    ```
    python mapping.py
    ```

- `graph_sim`

    *related module of Vision: Similarity Calculation*

    entry script:  affectedVersionIdentify_thread.py

    run:
    ```
    cd graph edit distance
    python affectedVersionIdentify_thread.py
    ```