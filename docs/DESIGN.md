# Design notes

Revenant is organised around one rule, which is that evidence flows in one direction. Bytes come from a source that is never written, pass through parsers that trust nothing they read, and leave as results that carry their own provenance. Everything below is an application of that rule to a particular part of the tool.

## How a scan flows

An image file is opened through a memory map in read only mode and hashed with SHA-256 and MD5 before anything parses it. An attached device takes a longer road, described under acquisition below, and ends up as the same kind of verified image. Parsers never see the file object. They receive a bounded reader that checks every offset, refuses reads outside the image, and hands out either the read only map or an immutable bytes object when a parser wants to search, so nothing a parser does can write through to the evidence.

Detection runs next. JFFS2, UBIFS and LittleFS are recognised from checksummed structures, which makes a match dependable, while YAFFS and SPIFFS are recognised from layout hints that can match by accident. The heuristic carvers therefore run only when none of the strong ones claimed the image. The signature carver always runs, because a JPEG or a SQLite database can sit in any image whatever filesystem surrounds it.

Each carver yields artifacts, and the engine cleans their names, hashes their payloads, and appends them to the result. When every carver has finished, the engine removes signature finds whose bytes a filesystem carver already recovered, since the filesystem copy carries a path and a state while the carved copy carries only an offset. The finished result goes to the interface, the command line, the JSON manifest, the export writer and the PDF report, which all read the same data classes.

## Defense in depth

The layers are independent, so a mistake in one does not open a path through the others.

Evidence is never modified. Beyond the read only map and the bounded reader, a test hashes a demo image and records its modification time before and after a full scan and fails if either changes.

Devices are copied before they are analysed. The destination image is created exclusively, so an existing file cannot be overwritten, and reads are aligned to 4 KiB because Windows rejects unaligned reads from raw drives. The copy is hashed while it is written, hashed again from disk afterwards, and the report states whether the two agree. A cancelled or failed acquisition deletes the partial image. An early version also deleted the destination when it already existed, which would have destroyed an examiner's file, and a test written for exactly that case caught it, so the code now removes only a file that the same call created.

Every structure read from the image is treated as hostile. Records are accepted only after their checksums validate, using each filesystem's own convention, which differs in seed and final inversion between LittleFS, JFFS2 and UBIFS. Hard limits cap the number of records walked, the number of artifacts kept, the size of one payload, the depth of any nested walk, and the number of historic versions rebuilt per file. Decompression is bounded inside the decompressor rather than checked afterwards, so a node that claims a few bytes and inflates to gigabytes stops at the cap, and a test feeds such a bomb to prove it. Every chain walk keeps a visited set, which turns a crafted loop into a clean stop.

Recovered names are untrusted input as well. Control characters are replaced before a name reaches the table, a log line or the report, and the report escapes markup in every value. Exported files get sanitised names inside the chosen folder, the resolved path is checked to stay inside that folder, reserved Windows device names are prefixed, and nothing is ever overwritten. The manifest neutralises values that a spreadsheet would execute as a formula.

Failures are contained. Each carver runs inside its own error handling, a guardrail that trips is recorded in the audit trail, and the scan continues with the remaining carvers. Scans run on a worker thread with a cancel flag, so a slow or hostile image never freezes the window.

The session keeps an append only audit trail of what was opened, hashed, detected, carved, merged and exported. It records sizes and hashes but never content, so the trail in the report can be shared without leaking recovered data.

## LittleFS

LittleFS stores metadata in pairs of blocks, each holding a revision count followed by a log of commits that end in a CRC. The carver walks every block in the image with littlefs's own CRC convention, flips the expected valid bit after each commit exactly as littlefs does, and stops at the first tag that fails, which is where littlefs itself stops trusting a block. Replaying the commits then follows the create and delete tags, which shift entry ids up and down. Treating ids as fixed was the most damaging bug in the first version of this carver, because an in place deletion would have shown the next file under the deleted file's name.

Pairs are discovered from directory entries and tail pointers, the newer block of each pair is chosen by comparing revision counts as sequence numbers, and a breadth first walk from the root pair gives the live tree. Directories that were deleted still get paths, resolved through the older commits that named them. Larger files live in CTZ skip lists, and the carver reads them backwards from their head block using the same index arithmetic as `lfs_ctz_index`.

Content from a stale commit may point at blocks that were reused, so every recovered chain is checked three ways. Every block after the first carries extra skip pointers, and those must agree with the chain that was walked. The supposed first block must not open with a valid block number, since a genuine first block holds only file data. The recorded length must not run into erased space, which is what happens when a later and shorter file took over the blocks. Any failed check drops the item to low confidence.

After compaction, no commit may name a file at all, yet its data blocks often survive. The carver collects blocks that no metadata and no recovered chain claims, links them by their back pointers, validates each chain by its skip pointers, and reports the result as orphaned, with the length taken from where erased space begins.

## JFFS2

The carver searches for node headers on four byte boundaries, detects endianness from the magic, and validates the header, node and data CRCs with the kernel's convention of a zero seed and no final inversion. On NOR flash the kernel obsoletes a node by clearing one bit in its type field after the fact, so the header CRC is checked with that bit restored and marked nodes are read like any other.

Files are rebuilt per inode by replaying data nodes in version order over an extent list, truncating to the size recorded in each node. Replay matters because a later node can shrink a file, and simply stacking nodes would leak stale bytes into live content. Whenever a node is about to overwrite or truncate earlier content, the file as it stood just before is kept as an obsolete version named with its version number. Directory entries are ordered by version per parent, an entry that points at inode zero is an unlink, and an inode with no remaining name is reported as deleted with its old path.

## UBIFS

UBIFS nodes are validated with their CRC on eight byte boundaries, and inode, data and directory entry nodes are decoded with the kernel's layouts. The newest directory entry for each name wins by sequence number, an entry pointing at inode zero is an unlink, and an inode whose newest node has a link count of zero is deleted. Its size comes from the newest node that still had a link, since the final node of a deleted inode can record zero. Blocks are rebuilt per inode with the newest sequence number winning, older copies of a block are reported as obsolete, and blocks past the recorded size are kept as truncation remnants.

The on flash index is not rebuilt, so live and obsolete labels come from sequence numbers rather than from the tree UBIFS itself would consult. A rewritten index node or an unusual commit order could make that inference wrong, which is why UBIFS items never get high confidence.

## SPIFFS

Page and block sizes are chosen when a SPIFFS image is built and are not stored in it, so the carver tries the common geometries and keeps the one that yields the most valid object index headers. Flags are active low, a page counts as used once its used bit is cleared, and deletion clears the deleted bit in place, which leaves the bytes readable. Files are rebuilt from data pages by span index without relying on the index table layout, live pages are preferred, and stray pages from earlier versions are reported as obsolete fragments. The layout was checked against images built by Espressif's spiffsgen rather than against images the parser's own author wrote.

## YAFFS2

Object headers are read on chunk boundaries for 512, 1,024, 2,048 and 4,096 byte chunks, with and without spare bytes in the layout. When YAFFS unlinks a file it rewrites the header under its unlinked or deleted pseudo directory, objects 3 and 4, and those headers are reported as deleted. Data chunks are tied to files by tags in the spare area, which a plain image often lacks, so the carver recovers names, sizes and timestamps and leaves content to the signature carver rather than guessing.

## Signature carving

Each magic is searched with the image's native find, which scans a large image in seconds. Finding where a file ends is the real work. PNG chunks and JPEG markers are walked, ZIP archives close at their end record and are checked against the central directory, gzip, xz and bzip2 streams are decoded to their trailers under an output cap, and SQLite, ELF and RIFF sizes come from their headers. A PEM block ends at the END line whose label matches its BEGIN line. Three byte magics such as JPEG and gzip are kept only when their structure validates, a payload that is mostly erased bytes is dropped, and hits inside a file already validated end to end are skipped, which stops a ZIP's contents from appearing twice.

## What the confidence levels mean

High means the structure and its checksums line up. Medium means the content looks complete but part of it could not be verified, and low means the item is partial, damaged, or probably overwritten. On 30 LittleFS benchmark images every high confidence remnant was byte exact, 97.7 percent of medium ones were, and none of the low ones were, and the benchmark document gives the counts.
