# Revenant Benchmark Summary

Rates for deleted and superseded versions. Recall and baseline recall count only
versions whose bytes still existed in the image, since erased data cannot be recovered
by any tool.

| Suite | Later writes | Images | Versions | Still on flash | Recall | Labelled right | Byte exact | Path correct | Live mount baseline | Unattributed |
|---|---|---|---|---|---|---|---|---|---|---|
| jffs2 | 0 | 10 | 317 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 0 |
| littlefs | 0 | 10 | 350 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 0 |
| littlefs | 50 | 10 | 629 | 98.1% | 100.0% | 97.1% | 100.0% | 98.4% | 0.0% | 0 |
| littlefs | 200 | 10 | 1659 | 61.1% | 100.0% | 57.1% | 100.0% | 57.5% | 0.0% | 0 |
| littlefs | 800 | 10 | 5933 | 21.5% | 100.0% | 48.5% | 97.2% | 46.4% | 0.0% | 31 |
| samples | 0 | 4 | 9 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 0 |

Live files

| Suite | Later writes | Live recall | Live byte exact | Median scan ms |
|---|---|---|---|---|
| jffs2 | 0 | 100.0% | 100.0% | 4.3 |
| littlefs | 0 | 100.0% | 100.0% | 16.0 |
| littlefs | 50 | 100.0% | 100.0% | 14.9 |
| littlefs | 200 | 100.0% | 100.0% | 14.8 |
| littlefs | 800 | 100.0% | 100.0% | 13.9 |
| samples | 0 | 100.0% | 100.0% | 8.2 |
