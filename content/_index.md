---
# Leave the homepage title empty to use the site title
title: ""
date: 2022-10-24
type: landing

design:
  # Default section spacing
  spacing: "6rem"

sections:
  - block: resume-biography-3
    content:
      # Choose a user profile to display (a folder name within `content/authors/`)
      # username: admin
      text: ""
      # Show a call-to-action button under your biography? (optional)
      # button:
      #   text: Download CV
      #   url: uploads/resume.pdf
    design:
      css_class: light
      background:
        color: black
        image:
          # Add your image background to `assets/media/`.
          filename: visionlogo5.jpg
          filters:
            brightness: 0.9
          # size: cover
          size: full
          # size: 0.6
          position: center
          parallax: false
  - block: collection
    id: news
    content:
      title: Recent News
      subtitle: ''
      text: ''
      # Page type to display. E.g. post, talk, publication...
      page_type: post
      # Choose how many pages you would like to display (0 = all pages)
      count: 4
      # Filter on criteria
      filters:
        author: ""
        category: ""
        tag: ""
        exclude_featured: false
        exclude_future: false
        exclude_past: false
        publication_type: ""
      # Choose how many pages you would like to offset by
      offset: 0
      # Page order: descending (desc) or ascending (asc) date.
      order: desc
    design:
      # Choose a layout view
      view: date-title-summary
      # Reduce spacing
      spacing:
        padding: [1, 0, 0, 0]
  - block: markdown
    id: intro
    content:
      # filters:
      #   folders:
      #     - publication
      # subtitle: ''
      text: |-
        ![approach](approach.png)
        Vulnerability reports play a crucial role in mitigating open-source software risks. Typically, the vulnerability report contains affected versions of a software. However, despite the validation by security expert who discovers and vendors who review, the affected versions are not always accurate. Especially, the complexity of maintaining its accuracy increases significantly when dealing with multiple versions and their differences. Several advances have been made to identify affected versions. However, they still face limitations. First, some existing approaches identify affected versions based on repository-hosting platforms (i.e., GitHub), but these versions are not always consistent with those in package registries (i.e., Maven). Second, existing approaches fail to distinguish the importance of different vulnerable methods and patched statements in face of vulnerabilities with multiple methods and change hunks.
      title: 'Introduction'
    design:
      columns: '1'

  - block: collection
    id: modules
    content:
      title: Modules
      filters:
        folders:
          - modules
        featured_only: false
    design:
      # view: card
      view: article-grid
      columns: 3
      # rows: 2
      
  - block: collection
    id: groundtruth
    content:
      title: Ground Truth
      filters:
        folders:
          - groundtruth
        featured_only: false
    design:
      view: article-grid
      columns: 3

  - block: collection
    id: approach
    content:
      title: SOTA Approaches
      text: ""
      filters:
        folders:
          - relatedwork
        exclude_featured: false
    design:
      view: citation

  - block: collection
    id: vuldb
    content:
      title: SOTA Vulnerability DBs
      text: ""
      filters:
        folders:
          - vuldb
        exclude_featured: false
    design:
      view: citation

  - block: collection
    id: evaluation
    content:
      title: Evaluation
      filters:
        folders:
          - evaluation
    design:
      view: article-grid
      columns: 3
      rows: 2
---
