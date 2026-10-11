# What Revenant Is and How It Works

A plain walkthrough of the tool, written so that someone who has never opened the code can still follow what it is, what it does, and how its pieces fit together. The last two sections line up what the project set out to build against what the tool actually delivers, with nothing hidden.

## What Revenant Is

Revenant is a desktop program that reads a raw dump of flash memory and brings back files that the device has already thrown away. It runs on Windows and Linux, it has a normal windowed interface, and it also has a command line for people who prefer to script it. You point it at an image of the flash, either a file you already have or a device you attach, and it returns the files it could recover along with a report that records where each one came from.

The important word in that description is raw. Revenant does not work on the tidy filesystem the device shows you. It works on the underlying flash, where deleted and replaced data often survives for a long time because of how flash storage is built. That surviving data is the whole point of the tool, and everything inside it exists to find that data and hand it back with enough provenance that an examiner can stand behind it.

## The One Job It Does That Ordinary Tools Do Not

When investigators pull files out of firmware today, they reach for tools such as binwalk together with extractors like jefferson for JFFS2 or ubi_reader for UBIFS. Those tools are good at one thing, which is rebuilding the live filesystem, the set of files the device would show you if it booted. They walk the current directory tree and reconstruct what is still valid, and then they stop.

Revenant starts exactly where they stop. Flash memory cannot overwrite a page in place, so when a file changes or gets deleted, the old contents are not wiped, they are simply marked as no longer current and left sitting in the array until the device eventually reclaims that space. An ordinary extractor ignores those obsolete and deleted records because they are not part of the live tree. Revenant reads them on purpose. That single decision, to recover what the filesystem believes it has discarded rather than only what it still presents, is the contribution the whole project rests on.

## How You Actually Use It

There are two ways in, and they lead to the same engine underneath.

The windowed version is what most people will use. You open Revenant, you choose an image file or an attached disk, you optionally fill in a case name and your name as the examiner, and you press Start Scan. A progress bar moves while the work runs, you can cancel at any point, and when it finishes you get a table of recovered items. Each row shows what state the item was in, how much to trust it, where in the image it came from, and its recovered path or name. You can click a row to see the text and a hex view of the recovered bytes, and you can export the recovered files together with a PDF report.

The command line does the same work without the window, which is what you want for repeatable runs and for scripting. A scan looks like `python -m revenant.cli scan device.img --report --export out_dir`, and there are sibling commands for listing attached disks and for acquiring a device into an image before scanning it. The command line is also what the benchmark harness drives when it measures the tool against known ground truth.

## What Happens Inside When You Press Scan

The engine runs four stages in order, and they are the four stages the project set out to build.

First it works out which filesystem is present. It does this by looking for real on medium signatures, for example the `0x1985` marker that begins every JFFS2 node or the magic number that opens a UBIFS node, rather than trusting any header a firmware packer might have written on top. Filesystems that are recognised from checksummed structures are treated as dependable, and the softer ones only engage when none of the strong matches fired, which keeps false detections down.

Second it walks every record in the medium. This is the stage that separates Revenant from the ordinary extractors, because it does not stop at the live tree. It collects nodes that were flagged obsolete, earlier versions that a later write superseded, and orphaned entries whose parent directory is already gone.

Third it reconstructs the files. It ties each fragment back to whatever metadata still survives, which can include the inode number, the name, a version or sequence counter, and a timestamp, and where a file was written across several generations it reassembles the chain. When the naming metadata has itself been erased, it still recovers the data by following the file's own internal back pointers, and it reports that item honestly as orphaned rather than inventing a path for it.

Fourth it writes everything out. The recovered files can be exported to a folder, and a PDF report records, for each item, the byte offset it came from, whether it was live or obsolete or deleted, a confidence flag, and a SHA-256 hash that fixes the recovered bytes so the same result can be checked later. The report also carries the evidence hashes and a chain of custody log, so it reads as an exhibit rather than a printout.

## The Files and What Each One Does

The code is about 5,700 lines of Python, organised so that each file has one clear job. Here is the whole tree in plain terms, grouped the way the program is actually layered.

### The Way In

`revenant/__main__.py` and `revenant/app.py` are the front door. They start the windowed application, and they hold the small amount of glue that wires the interface to the engine. `revenant/version.py` is a tiny file that just records the version number and the report schema, so every output can say which build produced it.

`revenant/cli.py` is the command line. It parses the scan, list, and acquire commands, calls the engine, and prints or saves the result. This is the file the benchmark harness talks to, and it is the one to read if you want to understand the tool without touching the interface.

### The Core Engine

`revenant/core/engine.py` is the conductor. It opens the evidence read only, asks the detector which carvers apply, runs each carver inside shared safety limits, merges duplicate finds, and gathers everything into one result. It writes the chain of custody log as it goes, so the record is made while the work happens rather than reconstructed afterwards.

`revenant/core/evidence.py` handles the source under examination. It memory maps an image read only, and when you scan a real device it streams the device into an image file, hashes it during the copy, and verifies that the written image matches the copy before anything else touches it. This file is careful in a way that matters for forensics, since it will only ever delete a partial file that its own current call created.

`revenant/core/security.py` is the safety layer that every other part leans on. It bounds every read so a corrupt length field cannot make the tool allocate gigabytes, it sanitises recovered names so a malicious filename cannot escape the output folder, it makes exported CSV safe against formula injection, and it holds the hashing helpers and the audit log. Treating the input as hostile is the whole posture of this file.

`revenant/core/models.py` defines the shapes that everything else passes around, the recovered Artifact with its state and confidence and offset and hash, the scan statistics, the evidence record, and the case information. Keeping these as plain data makes them easy to serialise, test, and hand to the report writer.

`revenant/core/export.py` writes recovered files to disk and builds a manifest CSV, re-hashing each file after it is written so the manifest reflects what actually landed on disk.

`revenant/core/report.py` builds the PDF. It lays out the evidence identity and hashes, a summary, the table of recovered items with their provenance, short previews of the most important content, an honest per parser note on how far to trust each result, and the chain of custody. It is written to read like a person produced it, because a report that sounds machine generated invites doubt about the work behind it.

`revenant/core/disks.py` enumerates attached storage so the tool can offer you a device to acquire. On Linux it reads the MTD entries, and on Windows it asks the system for physical drives.

### The Filesystem Carvers

These live in `revenant/core/filesystems/` and they are the heart of the recovery. Each one understands the on medium layout of a single flash filesystem and knows how to surface its discarded records.

`base.py` is the short contract every carver follows, and `detect.py` is the dispatcher that decides which carvers to run against a given image. The strong, checksum backed carvers are tried first, and the softer ones only run if none of those matched.

`jffs2.py` reads JFFS2, the log structured filesystem common on raw NOR and NAND. It validates each node with the kernel's own CRC, replays data nodes in version order so that truncations are respected, and keeps each earlier state that a later write changed.

`ubifs.py` reads UBIFS, which sits on top of UBI on NAND. It validates each node's CRC and rebuilds files per inode, and because the live status of a node depends on the on flash index, it treats its obsolete labels as a careful best estimate rather than a certainty.

`littlefs.py` reads LittleFS, the small failsafe filesystem used on microcontrollers and SPI NOR parts. It is the most developed carver in the tool. It replays every CRC checked commit, follows the identifier shifts that LittleFS uses, reads the CTZ skip lists that hold larger files, and, when compaction has erased the commit that named a file, rebuilds the file from its own back pointers and reports it as orphaned. That last ability is what keeps recall high even after heavy later writing.

`spiffs.py` reads SPIFFS, another microcontroller filesystem, by parsing its page headers and deletion flags and reassembling files by their span index.

`yaffs.py` reads YAFFS2. It recovers the object headers that carry a file's name, parent, recorded size, and modification time, and it reports files that were moved under the unlinked or deleted pseudo directories as deleted. It deliberately does not try to reassemble file content from the per chunk tags, because those tags live in the spare area of each NAND page and a plain image may not carry them. The honest boundary of this carver is discussed in its own section below.

`signature_carver.py` is the safety net. It scans the whole image for known file types by their magic bytes and their structural end markers, which recovers real content that no filesystem parser managed to place. When it finds something a filesystem carver already recovered with a proper name, the engine folds the duplicate away so the same bytes are not reported twice.

### The Interface

`revenant/ui/main_window.py` is the window itself, with the scan worker that runs off the main thread so the interface stays responsive, the cancel button, the case dialog, the results table, and the text and hex detail views. `revenant/ui/models.py` feeds the results table and lets you filter it, and `revenant/ui/theme.py` holds the colours and styling that tie the window and the report together.

### The Bench and the Tests

`tools/workload.py` generates flash images with an exact record of everything written, changed, and deleted, which is what makes honest measurement possible. `tools/run_benchmark.py` drives the tool over those images and scores it. `tools/make_test_images.py` builds the small demo images that ship with the tool, `tools/nandsim_bench.sh` is the script that produces real kernel JFFS2 and UBIFS images on a Linux host, and `tools/third_party/` holds the vendored SPIFFS image generator with its licence. The `tests/` folder holds 52 tests that cover the carvers, the engine, the security layer, the command line, and the interface.

## How the Files Connect

The flow through the program is easier to hold in your head as a path from the evidence to the report.

You start at the interface or the command line, and both of them call into `engine.py`. The engine asks `evidence.py` to open the image read only and hash it. It then asks `detect.py` which carvers apply, and `detect.py` reads a small opening region through the bounded reader in `security.py` to decide. The engine runs each chosen carver from the `filesystems` folder, and every carver yields `Artifact` objects defined in `models.py`, reading only through the bounded reader so nothing can run away with memory. The engine merges duplicate finds, tallies the statistics, and returns one `ScanResult`. From there, `report.py` turns that result into a PDF and `export.py` writes the recovered files and their manifest. The audit log in `security.py` has been collecting a timestamped record the entire way through, and it becomes the chain of custody section of the report.

If you read only one file to understand the tool, read `engine.py`, because every other part connects to it.

## What It Set Out to Do, What It Has, and What It Does

This is the honest audit. The left column is what the project set out to build, the middle column is what exists in the code, and the right column says in one line what actually happens when you run it.

| What it set out to do | What the tool has | What it does when you run it |
|---|---|---|
| Take a raw flash image as input, from a file or an attached device | `engine.py`, `evidence.py`, `disks.py` | Opens an image read only, or acquires a device into a verified image first, then scans |
| Stage one, identify the filesystem by on medium signatures rather than headers | `detect.py` and each carver's detect method | Recognises JFFS2, UBIFS, and LittleFS from checksummed structures, YAFFS and SPIFFS from layout, ignores packer headers |
| Stage two, walk every record and collect obsolete, superseded, and orphaned entries | every carver in `filesystems/` | Returns deleted, obsolete, and orphaned items, not just the live tree |
| Stage three, reconstruct earlier and deleted versions and tie them to metadata | `jffs2.py`, `ubifs.py`, `littlefs.py`, `spiffs.py` | Rebuilds files per inode or per commit, keeps version order, reassembles chains, attaches path and time where they survive |
| Stage four, write a provenance report with offset, live or obsolete state, and a confidence flag | `report.py`, `export.py` | Produces a PDF with evidence hashes, per item offset, state, confidence, SHA-256, and a chain of custody |
| Support UBIFS, JFFS2, YAFFS, LittleFS, and SPIFFS | five carvers plus a signature carver | All five parse and detect, with the YAFFS limit noted below |
| Recovery rate against a ground truth deletion log | `tools/workload.py`, `tools/run_benchmark.py` | Scores recall of surviving remnants by unique tokens, currently 100 percent of surviving data across every churn level tested |
| Fidelity by hash for full recoveries and a percentage for partial ones | the exact and confidence scoring in the harness | Reports byte exact rate and a confidence label whose meaning is calibrated |
| Metadata accuracy for path, inode, and timestamp | added to the harness in this revision | Scores whether recovered paths match the truth path, reported two ways so orphans are not counted as failures |
| False positive count for invented fragments | the unattributed count in the harness | Counts recovered non live items that carry no real token, which stays at zero except under extreme churn |
| Baseline comparison against the existing extractors | the live mount baseline in the harness | Compares against the live tree an ordinary extractor would return, which recovers zero of the deleted remnants |
| Open source tool, reproducible dataset, dissertation | the packaged tool, the bench scripts, this documentation | The tool and the labelled image generator ship together, so any number can be reproduced |

Metadata accuracy, in the middle of that table, was the last gap to close. The harness measured recall, fidelity and false positives from the start but never scored path attribution, even though the tool recovers the metadata and the ground truth records the true paths. It does now, so every evaluation metric the project set out to report is actually produced.

## The One Place the Tool Is Narrower Than Its Scope

Honesty here is worth more than a clean table, and there is exactly one place where the built tool is narrower than the scope it set out to cover, which is YAFFS.

The intended scope included recovering YAFFS content using the per chunk tags that YAFFS keeps in the spare area of each NAND page. The tool recovers YAFFS object headers, which give you the file names, the parent directories, the recorded sizes, the modification times, and a clear marker on files that were unlinked or deleted. It does not reassemble the file data from the spare area tags, and it hands YAFFS file content to the signature carver instead of guessing at it.

There are two good reasons this is the right call rather than a shortcoming to paper over. The spare area tags only exist in a NAND dump that was captured with its out of band region intact, and many images in circulation do not carry that region at all, so a tag based reassembler would sit idle on the very images people most often have. More importantly, a parser that guessed at YAFFS content without the tags would produce exactly the kind of invented evidence a forensic tool must never produce. The tool therefore recovers what it can stand behind for YAFFS, which is the names and the deletion markers, and it says so plainly in the report and in the code. If anyone asks about YAFFS, that is the answer, and it is a stronger answer than an over claim would be.
