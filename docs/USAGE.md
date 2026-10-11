# Running Revenant and Reading What It Recovers

This is the working reference for actually using the tool after you unzip it. It covers the first run, every command and option with an example of each, how to read the confidence column so you trust the right files, and a plain explanation of the recovered zip files that come out around 256 KB and refuse to open. Keep it next to the tool, since the last section answers a question that will come up again on any real disk.

## Getting It Running

Whether you cloned the repository or unpacked a release archive, you get the same folder: the program under `revenant`, the launchers at the top, the sample images under `samples`, the committed benchmark run under `bench_results`, and the documentation under `docs`. Nothing is installed yet, and the first run is what sets the tool up.

The simplest way in is the launcher for your system. On Windows you double click `run_windows.bat`, on Linux you run `./run_linux.sh`, and on a Mac you open `run_macos.command`. The first time you do this the launcher builds a private Python environment inside the folder, in a hidden `.venv` directory, and installs what the tool needs from the Python package index. That first setup takes a minute or two and only happens once, and every later start is immediate. If the launcher cannot find Python it stops and tells you to install Python 3.10 or newer with the box that adds it to your PATH ticked, and then to run the launcher again.

If you would rather set it up by hand, the same thing happens with three commands from inside the folder.

```
python -m pip install -r requirements.txt
python -m revenant          # starts the windowed app
```

The one thing worth doing on your very first run, before you trust the tool on real evidence, is to point it at one of the sample images and confirm it recovers the planted files. That check takes ten seconds and tells you the install is sound.

```
python -m revenant.cli scan samples/littlefs_demo.img
```

You should see it detect littlefs and list a deleted `token.txt`, a deleted `snap_0001.jpg`, and an obsolete `log.txt`, which is the known content of that image. Once that works, the tool is ready for real images.

## The Three Ways to Run It

There is one engine underneath and three ways to reach it, and picking the right one is mostly about what you are pointing it at.

The windowed application is the normal way, and it is what the launcher starts. You open an image or pick an attached disk, you fill in the case details if you want them on the report, and you read the results in a table you can sort, filter, and export.

The command line is the same engine without the window, which is what you want for repeatable runs, for a machine with no display, or for scripting a batch of images. Every option below belongs to the command line.

The acquire path is a special case of both, used when the evidence is a live device rather than a file. It copies the device into a fresh image, hashes it during the copy, checks the written image against that hash, and only then scans it, so the original is never worked on directly.

## Every Command and Option

The command line has three commands, which are `disks`, `scan`, and `acquire`. Two options sit above all of them, and a shared block of output options is available on `scan` and `acquire`.

### The Global Options

`--version` prints the tool name and version and exits. `-v` or `--verbose` turns on the engine log messages, which is useful when you want to see what each carver did rather than only the result. You place these before the command, for example `python -m revenant.cli -v scan image.img`.

### disks, List What Is Attached

This command lists the storage the tool can see, with each device's path, size, and model, so you know what to hand to the acquire command. Reading raw devices needs administrator or root rights, and the command says so if you are not elevated.

```
python -m revenant.cli disks
```

On Windows the devices come back as `\\.\PhysicalDrive1` and similar, and on Linux they come back as `/dev/sdb` or `/dev/mtd0`. Be careful to read the size and model, because `PhysicalDrive0` is almost always your own system disk.

### scan, Examine an Image File

This is the command you will use most. It takes the path to an image file and runs the full examination on it.

```
python -m revenant.cli scan evidence.img
```

Its own option is `--no-hash`, which skips hashing the image before the scan. Hashing is on by default because the hash is what fixes the state of the evidence for the report, so only skip it when you are doing a quick throwaway look and do not need the record.

```
python -m revenant.cli scan evidence.img --no-hash
```

### acquire, Copy a Device Then Optionally Scan It

This command copies a whole device into a new image file and records its hashes, which is the correct first step when the evidence is a physical device rather than a file. It takes the device and the name of the image to create, and it will never overwrite an existing file.

```
python -m revenant.cli acquire \\.\PhysicalDrive1 case01.img
```

Its options are `--length`, which sets how many bytes to copy and defaults to the whole device when the size is known, and `--scan`, which runs the examination on the verified image straight after the copy so you do not need a second command.

```
python -m revenant.cli acquire /dev/sdb case01.img --scan --report reports
```

Acquiring a raw device needs administrator or root rights, so run this one elevated.

### The Shared Output Options

These work on both `scan` and `acquire`, and they decide what the run produces beyond the on screen table.

`--report FOLDER` writes the PDF forensic report into the named folder, with the evidence hashes, the recovered items and their provenance, and the chain of custody. `--json FILE` writes a full JSON manifest of every artifact, which is the machine readable form of the same result. `--export FOLDER` writes the recovered files to disk with a hashed manifest CSV, and by default it exports only the recovered items, not the live filesystem. `--export-all` widens that to include the live files too. `--limit N` sets how many rows the on screen table prints, defaulting to forty, and the full set is always in the JSON. `-q` or `--quiet` hides the progress lines.

A full run that produces everything at once looks like this.

```
python -m revenant.cli scan evidence.img --case "Case 01" --examiner "M S B Junaid" \
  --report out --json out/manifest.json --export out/files
```

The case, examiner, reference, and notes options are free text that only affect what appears on the report, so use them when the output is going into a file someone else will read.

### The Windowed Application Actions

The window exposes the same engine through a handful of actions, most with a keyboard shortcut. You open an image with Ctrl and O, you start the scan with Enter, you filter the results with F, you export the selected items with E, and you produce the report with R. A scan in progress can be cancelled at any time with the Cancel button, and a partial result is kept rather than thrown away. Clicking a row opens the text and hex views of that item's recovered bytes. When you have started the app with administrator rights the chip in the top corner reads Administrator session, which is the sign that attached disks will be readable.

## Reading the Output and the Confidence Column

Every recovered item carries two labels that decide how far to trust it, and reading them is the difference between a clean recovery and a folder of files that will not open.

The state says where the item stood when the image was taken. Live means it is still part of the active filesystem. Obsolete means an older version that a later write replaced. Deleted means it was removed from the filesystem. Orphaned means the data was recovered but its parent directory was gone, so there is no reliable path. Carved means it was found by a raw signature scan with no filesystem context at all.

The confidence says how much to trust the bytes. High means the structure validated from end to end, so the file is complete and you can rely on it. Medium means the end was located from a footer or a size field rather than full validation, so it is usually complete but part of it is unchecked. Low means there was no reliable end and the tool kept a bounded slice, so the item is very likely partial and may not open in the program that made it. The calibration behind these labels is strong, since across the benchmark every high confidence item was byte exact and no low confidence item ever was, so the labels are worth acting on.

The practical rule is to treat high and medium recoveries as usable files and to treat low confidence carves as leads rather than finished files. When you export, read the confidence column of the manifest CSV before you try to open anything, and start with the high confidence rows.

## Why Some Recovered Zip Files Are About 256 KB and Will Not Open

This one deserves a full explanation, because it is not a random glitch and it will happen again on any ordinary disk.

The files you saw were about 256 KB, which is 262144 bytes, and every one of them is a low confidence carve. That exact size is the tell. When the signature carver finds the four bytes that begin a zip local file header, it then searches forward for the end of central directory record, which is the small structure at the very end of a real zip that lists everything inside it. If it finds that record and the internal offsets line up, it recovers the whole archive and marks it high confidence, and that file opens normally. If it cannot find a valid end record, it does not invent one. It keeps a bounded slice of 256 KB from the signature onward and marks it low confidence, with the note that no reliable end was found. That slice is the first quarter megabyte of whatever started with a zip signature, and it is almost never a working archive, so your unzip tool looks for the central directory, finds none, and reports the archive as empty.

The reason this happened in bulk is worth being honest about, because it goes to the scope of the tool. Revenant is built for raw flash filesystems, the ones on microcontrollers and on embedded Linux devices that manage the flash directly. A physical hard drive is not that. It is managed storage with an ordinary filesystem such as NTFS or exFAT, and none of the flash filesystem carvers recognise it, so on a hard drive the only carver that runs is the signature carver. Signature carving is a net for content the filesystem parsers cannot place, and it works best when a file sits in one contiguous run. On a real hard drive a large zip is often split into fragments scattered across the disk, so the bytes physically following the zip header are not the rest of the zip, the end record is nowhere near, and the carve falls back to that 256 KB slice. On top of that, many things that are not plain zips begin with the same signature, since Word, Excel, and PowerPoint files, along with Java and Android packages, are all zip based, so some of those slices were never standalone zips to begin with.

So the short version is that the 256 KB empty zips are the tool telling you, through the low confidence label, that it found a zip like start it could not close. They are not a bug in the sense of the tool doing the wrong thing, they are the honest result of running a flash carver against a hard drive, which is outside what it was built for.

## What to Do About It

There are a few practical moves, in order of how much they help.

Filter by confidence first. In the window, use the filter to hide low confidence items, and on the command line read the confidence column of the manifest and keep the high and medium rows. The zip files that do open will almost all be high confidence, and filtering removes the empties in one step.

Match the tool to the medium. If the evidence is a normal hard drive or an SSD, a flash carver is the wrong instrument, and a filesystem aware recovery tool for NTFS or ext, or a general file carver built for managed disks such as PhotoRec, will do far better on fragmented files than signature carving can. Revenant earns its keep on raw flash dumps from the devices it targets, which is where the filesystem parsers do the heavy lifting and the recovery is reliable rather than best effort.

If you do want to look inside a low confidence slice, remember what it is, which is the first 256 KB from the signature. For a small office document that happened to be contiguous you can sometimes rename it and open it, but there is no guarantee, and anything larger than the slice is truncated by definition. Treat it as a fragment to inspect in a hex view, not as a recovered file.
