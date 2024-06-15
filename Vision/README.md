## All code, dataset, SOTA approaches and Vul DB for Vision

Vulnerability reports play a crucial role in mitigating open-source software risks. Typically, the vulnerability report contains affected versions of a software. However, despite the validation by security expert who discovers and vendors who review, the affected versions are not always accurate. Especially, the complexity of maintaining its accuracy increases significantly when dealing with multiple versions and their differences. Several advances have been made to identify affected versions. However, they still face limitations.
First, some existing approaches identify affected versions based on repository-hosting platforms (i.e., GitHub), but these versions are not always consistent with those in package registries (i.e., Maven). Second, existing approaches fail to distinguish the importance of
different vulnerable methods and patched statements in face of vulnerabilities with multiple methods and change hunks.

To address these problems, this paper proposes a novel approach, Vision, to accurately identify affected library versions (ALVs) for vulnerabilities. Vision uses library versions from the package registry as inputs. To distinguish the importance of vulnerable methods and patched statements, Vision performs critical method selection and critical statement selection to prioritize important changes and their context. Furthermore, the vulnerability signature is represented by weighted inter-procedural program dependency graphs that incorporate critical methods and statements. Vision determines ALVs based on the similarities between these weighted graphs. Our evaluation demonstrates that Vision outperforms state-of-the-art approaches, achieving a precision of 0.91 and a recall of 0.94. Additionally, our evaluation shows the practical usefulness of Vision in correcting affected versions in existing vulnerability databases


## 1. Ground Truth

This section contains the ground truth data we used.

To learn more about how the dataset was constructed as described in the paper, please visit the [1.groundtruth](https://github.com/vision-version/vision-version.github.io/tree/main/Vision/1.groundtruth) folder.

## 2. Methodology

This section details the main modules of our Vision framework, which include critical method selection, slicing, taint analysis, IPDG construction, and graph similarity calculations. 

For a deeper understanding of our methodology, please visit the [2.methodology](https://github.com/vision-version/vision-version.github.io/tree/main/Vision/2.methodology) folder.

## 3. Baseline

The baseline section comprises patched-based methods such as Verjava (not open sourced), V-SZZ (open sourced), and clone-based methods including V0Finder (open sourced), MVP (not open sourced), and Vuddy (open sourced).

As outlined in our paper, some approaches primarily target C/C++ and GitHub environments, but we have adapted them for Java and Maven.

For additional details, please visit the [3.baseline](https://github.com/vision-version/vision-version.github.io/tree/main/Vision/3.baseline) folder.

## 4. JAR Files

All JAR files used in our project are available on [Kaggle](https://www.kaggle.com/datasets/visionversion/all-jar-and-decompiled-script-for-vision). You can access and download the dataset directly from this platform.

## 5. Tool

The 'tool' folder contains tree-sitter, an AST (Abstract Syntax Tree) tool used in our Vision framework.

## 6. Evaluation

This section corresponds to the 'Evaluation' section of our paper. You can replicate our results by visiting the [6.evaluate](https://github.com/vision-version/vision-version.github.io/tree/main/Vision/6.evaluate) folder.