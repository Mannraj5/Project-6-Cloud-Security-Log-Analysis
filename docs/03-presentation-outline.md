# Presentation outline (7 slides, under 10 minutes)

| # | Slide | Content | ~Time |
|---|---|---|---|
| 1 | **Securing Database-as-a-Service** | Title, your name, one-line framing: *"The provider runs the database. You still decide who can reach it."* | 0:30 |
| 2 | **Background** | What DBaaS is, why it is adopted, the shared responsibility split as one diagram | 1:30 |
| 3 | **How cloud databases get exposed** | Misconfiguration vs. identity compromise; one real case study | 1:30 |
| 4 | **The controls — and where each one fails** | The controls table from the report, with the limitation column highlighted | 1:30 |
| 5 | **Detecting it: the lab** | One attack chain on a timeline: brute force → new country → privilege grant → database made public, with the alert each step raised | 2:00 |
| 6 | **What detection still misses** | The known limitations: fixed thresholds, uncorrelated spray, time zones, synthetic data | 1:30 |
| 7 | **Conclusions and recommendations** | 3–4 recommendations; one sentence on future work | 1:00 |

**Tips**

- Slide 5 is the strongest one for interviews. Run `python -m src.loglab` live, or use a screenshot
  of its output.
- Keep text to short phrases on the slides and say the detail out loud.
- Record in PowerPoint (*Slide Show → Record*), export to MP4, and upload as **unlisted** on YouTube
  so you can link it from the README.
