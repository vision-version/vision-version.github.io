---
title: RQ1 Effectiveness

# event: Hugo Blox Builder Conference
# event_url: https://example.org

# location: Hugo Blox Builder HQ
# address:
#   street: 450 Serra Mall
#   city: Stanford
#   region: CA
#   postcode: '94305'
#   country: United States

# summary: An example talk using Hugo Blox Builder's Markdown slides feature.
# abstract: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis posuere tellusac convallis placerat. Proin tincidunt magna sed ex sollicitudin condimentum. Sed ac faucibus dolor, scelerisque sollicitudin nisi. Cras purus urna, suscipit quis sapien eu, pulvinar tempor diam.'

# Talk start and end times.
#   End time can optionally be hidden by prefixing the line with `#`.
date: '2024-06-14T13:00:00Z'

# authors:
#   - admin

tags: [RQ1]

# Is this a featured talk? (true/false)
featured: false
---

- folder of effectiveness: RQ1

    to evaluate and compare vision with SOTAs, you should first cd the [folder](https://github.com/vision-version/vision-version.github.io/tree/main/Vision/6.evaluate/effectiveness)
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