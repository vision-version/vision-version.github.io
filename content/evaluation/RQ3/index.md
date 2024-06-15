---
title: RQ3 Parameter Sensitivity Study

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
# date: '2030-06-01T13:00:00Z'
# date_end: '2030-06-01T15:00:00Z'
# all_day: false

# Schedule page publish date (NOT talk date).
publishDate: '2024-06-14T11:00:00Z'


tags: [RQ3]

---
you should first cd the [folder](https://github.com/vision-version/vision-version.github.io/tree/main/Vision/6.evaluate/threshold_sensitivity)

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