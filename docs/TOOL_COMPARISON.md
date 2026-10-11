# How Revenant Compares With Existing Recovery Tools

This file sets Revenant against the tools an examiner would otherwise reach for. The comparison is built two ways. The capability matrix comes from each tool's own documentation and source, so it states what each one is designed to do rather than guessing. The quantitative result comes from the controlled benches in this project, where the live tree that a conventional extractor returns was measured on the same images Revenant was scored on, so the two approaches meet on identical data with an exact ground truth behind them.

A word on scope before the tables. The tools below were not all run head to head on the same seized device, because several of them target a different medium entirely and two are closed commercial suites that cannot be scripted into this harness. Comparing them on raw flash would tell you little, since most were never built for it. What the comparison does instead is place each tool on the axis that matters for this work, which is the recovery of deleted and superseded records from raw flash filesystems, and show where each one stops. That axis is where Revenant was designed to go further, and the measured baseline shows by exactly how much.

## The Capability Matrix

| Tool | Primary target | Recovers deleted and superseded filesystem records | Parses raw flash filesystems | Ties remnants to path, inode, version, time | Per item provenance, offset, state, confidence, hash | Open source |
|---|---|---|---|---|---|---|
| Revenant | Raw NAND and SPI NOR flash | Yes | Yes, five filesystems | Yes | Yes | Yes |
| binwalk with jefferson, ubi_reader, yaffshiv | Firmware images and raw flash | No, live tree only | Yes, for the live tree | Live files only | No | Yes |
| PhotoRec | Any disk image, byte level | Carved bytes only, no filesystem record | No | No, carved files get generic names | Offsets in a log | Yes |
| Scalpel | Any disk image, byte level | Carved bytes only, no filesystem record | No | No | Offsets in a log | Yes |
| The Sleuth Kit and Autopsy | Managed disk filesystems | Yes, for NTFS, FAT, ext, HFS | No | Yes, for supported filesystems | Yes | Yes |
| FTK and EnCase | Managed disks and mobile | Yes, for supported filesystems and carving | No | Yes | Yes | No |

The matrix says the thing plainly. No tool other than Revenant recovers deleted and superseded records from a raw flash filesystem and ties them back to their metadata with a per item provenance record. The firmware tools parse the right filesystems but return only the live tree. The carvers reach any image but recover loose bytes with no filesystem context. The two forensic suites and the open Sleuth Kit are strong on managed disks, where they recover deleted files and unallocated content well, but they do not read the raw NAND and SPI layouts where wear leveling leaves its remnants, so the obsolete node that holds a deleted version is invisible to them.

## The Measured Difference

The capability matrix is a design comparison. The number that gives it weight comes from the controlled benches, where the live tree that binwalk with its extractors would return was read from every image and scored against the same deletion log as Revenant. A conventional extractor returns the current filesystem, so by construction it recovers none of the deleted or superseded versions, and the measurement confirms it at zero on every image. Revenant recovers every remnant that still survives on the medium.

| Later writes | Remnant versions still on the flash | Recovered by a conventional live extractor | Recovered by Revenant |
|---|---|---|---|
| 0 | 350 | 0 | 350 |
| 50 | 617 | 0 | 617 |
| 200 | 1014 | 0 | 1014 |
| 800 | 1275 | 0 | 1275 |

Every entry in the last column is a deleted or superseded file version that an ordinary extraction would not return, recovered here with a state, a confidence label, and in most cases a path. The gap between the third and fourth columns is the contribution, and on remnant recovery it is the whole of what survived.

## Tool by Tool

**binwalk with jefferson, ubi_reader, and yaffshiv.** binwalk drives a set of extractors over a firmware image, and for flash filesystems it hands off to jefferson for JFFS2, ubi_reader for UBIFS, and yaffshiv for YAFFS [1]. Each of these walks the current directory tree and rebuilds the files that are still valid, which is what firmware analysis needs. None of them is built to surface the obsolete and superseded nodes that carry deleted history, so a file that was replaced or removed before the image was taken does not appear in their output. This is the closest prior work to Revenant, and the measured baseline above is exactly what this class of tool returns.

**PhotoRec.** PhotoRec recovers files by their signatures from any disk image, independent of the filesystem [2]. On a medium whose filesystem it cannot read, which includes raw flash, signature carving is the only option, and it is the same fallback Revenant keeps for content its parsers cannot place. What PhotoRec does not do is reconstruct a filesystem record. A recovered file arrives with a generic name and no path, no version history, and no statement of whether it was live or deleted, because that information lives in filesystem structures the carver never parsed. On a fragmented file it recovers only the first contiguous run.

**Scalpel.** Scalpel is a header and footer file carver in the same family, tuned for speed and low memory use [3]. Its strengths and its limits match PhotoRec for the purpose here. It carves bytes, not filesystem history, and it has no model of flash wear leveling, so a superseded version sitting in an obsolete page is just more unlabelled data to it.

**The Sleuth Kit and Autopsy.** The Sleuth Kit is the open foundation for a large part of filesystem forensics, and Autopsy is its graphical front end [4]. It recovers deleted files, reads unallocated space, and reconstructs orphaned entries well, but it does this for managed disk filesystems such as NTFS, FAT, ext, and HFS. It reads the logical block device a controller presents, not the raw NAND behind a flash translation layer, so the physical obsolete pages that this project targets are not on the surface it examines. It is the right tool for a laptop disk and the wrong tool for a raw NAND dump.

**FTK and EnCase.** These are the two dominant commercial forensic suites, strong on managed disks and mobile acquisition, with mature file recovery and carving [5, 6]. They are closed, so they cannot be scripted into this harness, and they share the same boundary as the Sleuth Kit for the purpose here. Their recovery works on the filesystems a storage controller exposes, not on the raw flash filesystems and obsolete node structures that wear leveling produces on unmanaged NAND and SPI flash. On the managed storage they target they are capable tools, which is a different problem from the one Revenant addresses.

## Why There Are No Fabricated Head to Head Numbers

A table of recovery percentages for FTK or EnCase on these flash images would be easy to write and impossible to defend, because those tools were not run on this data and most of the tools here were never built for raw flash at all. Inventing such numbers would be data fabrication, and in a dissertation it is the kind of thing that ends badly under examination. The honest comparison is stronger anyway. The capability matrix shows, from each tool's own documentation, that none of them recovers superseded flash records with metadata and provenance, and the measured baseline shows a conventional extractor recovering zero remnants on the exact images Revenant was scored on. That is a real result, it survives a viva, and it puts Revenant where the evidence actually places it.

## References

[1] ReFirmLabs, binwalk firmware analysis tool, with the jefferson, ubi_reader, and yaffshiv extractors. https://github.com/ReFirmLabs/binwalk

[2] C. Grenier, PhotoRec, CGSecurity. https://www.cgsecurity.org/wiki/PhotoRec

[3] G. G. Richard III and V. Roussev, Scalpel, A Frugal, High Performance File Carver, Digital Forensic Research Workshop (DFRWS), 2005.

[4] B. Carrier, File System Forensic Analysis, Addison-Wesley, 2005, and The Sleuth Kit and Autopsy. https://www.sleuthkit.org

[5] Exterro (formerly AccessData), Forensic Toolkit (FTK).

[6] OpenText (formerly Guidance Software), EnCase Forensic.
