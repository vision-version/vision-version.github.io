---
title: RQ2 Ablation Study

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
publishDate: '2024-06-14T12:00:00Z'


tags: [RQ2]

---
  you should first cd the [folder](https://github.com/vision-version/vision-version.github.io/tree/main/Vision/6.evaluate/ablation)

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