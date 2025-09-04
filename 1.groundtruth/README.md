## How to Start

- `PatchCollect.json`: Contains all CVEs related to Maven with patches. We further refine this data by merging the ground truth from VerJava and V-SZZ, and then collecting Proof of Concept (PoC) exploits.

- `verjava_gt` and `vszz_gt` folders: These folders contain the ground truth data collected by VerJava and V-SZZ, respectively. We incorporate this data into our overall ground truth.

- `testcase-trigger` folder: Utilizes JUnit to exploit the CVEs and propagate the test case across all jar versions.

- `trueresult.json`: Represents the final ground truth, compiled by considering inputs from researchers and collected PoCs.