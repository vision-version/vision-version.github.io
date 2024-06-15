The folder can exactly match the evaluation of RQ1, RQ2, RQ3, and RQ4 in our paper.

- folder of kappa: kappa in paper

- folder of effectiveness: RQ1

    to evaluate and compare vision with SOTAs, you should first cd the [folder]()
    ```
    cd ./effectiveness
    ```

    To evaluate our tool:
    ```
    python evaluate_ourtool.py
    ```

    To evaluate vulnerability databases, patch-based methods, clone-based methods and Vision-github, you can run
    ```
    python  evaluate_theirtool.py
    ```
    
    To evaluate "Effectiveness w.r.t CWE Types" in Paper,
    ```
    python evaluate_type.py
    ```

    To evaluate "Effectiveness w.r.t Changed Methods" in our paper,
    ```
    python evaluate_number.py
    ```

    To evaluate "Effectiveness w.r.t Changed Types" in our paper,
    '''
    python evaluate_pure.py
    '''

- folder of ablation: RQ2

    `sortresults_without_all.json` means <b>(CM)</b> in paper

    `sortresults_without_cg.json` means <b>(CR)</b> in paper

    `sortresults_without_ref.json` means <b>(EF)</b> in paper

    `sortresults_without_unixcoder.json` means <b>(LD)</b> in paper

    `sortresults_intra_1.json` means <b>(CS)</b> in paper
    
    <b>notice</b>: sortresults_intra_1 is also the intra weight set to 1 in sensitivity analysis, ablation critical path means regarding the critical path as the same important as the sliced path.

    To evaluate "Ablation"(RQ2) in our paper,
    ```
    cd ./ablation
    python ablation.py
    ```
- folder of threshold_sensitivity: RQ3

    `sensitivity_hits.py` point Figure 5(a) in RQ3 

    `sensitivity_intra.py` point Figure 5(b) in RQ3 

    `sensitivity_inter.py` point Figure 5(c) in RQ3

    `sensitivity_vul.py` point Figure 5(d) in RQ3 

    To evaluate "parameter sensitivity"(RQ3) in our paper,
    ```
    cd ./threshold_sensitivity

    python sensitivity_hits.py

    python sensitivity_intra.py

    python sensitivity_inter.py

    python sensitivity_vul.py
    ```    

- folder of efficiency: RQ4
    [efficiency.csv](https://github.com/vision-version/vision-version.github.io/blob/main/Vision/6.evaluate/efficiency/efficiency.csv)

- folder of usefulness: RQ5

    to evaluate the usefulness, you should
    ```
    cd  usefulness

    python evaluation_db.py
    ```
### All the results are calculated by the IPDG we generated, you can download it from [kaggle](https://www.kaggle.com/datasets/visionversion/all-ipdg-for-ablation-and-sensitivity-analysis) 

