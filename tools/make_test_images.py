"""Build the labelled demo images that ship in the samples folder.

Each image comes with a truth file listing every version of every file, its
final state, and a unique token, plus whether that token still exists in the
raw image. The LittleFS image is produced by the reference implementation with
a realistic SPI flash configuration. The SPIFFS image is produced by Espressif's
own spiffsgen, and the deletion is applied by clearing exactly the bits SPIFFS
clears when it deletes a file. The JFFS2 and UBIFS images are written node by
node with the kernel checksum conventions, since those filesystems need a Linux
host with nandsim for a faithful run, which docs/BENCHMARKS.md walks through.

Run it directly to rebuild everything in samples.
"""

from __future__ import annotations

import io
import json
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
sys.path.insert(0, str(ROOT))

from tools.workload import LFS_CONFIG, JFFS2Writer, Tracker, UBIFSWriter  # noqa: E402


def _text(t: Tracker, text: str) -> tuple[str, bytes]:
    t.counter += 1
    token = f"RVN-{t.prefix}-{t.counter:05d}"
    return token, f"{token} {text}".encode()


def _long(t: Tracker, label: str, size: int) -> tuple[str, bytes]:
    token, head = _text(t, label)
    body = bytearray(head)
    n = 0
    while len(body) < size:
        body += f" row{n:05d},temp=21.{n % 10},hum=4{n % 10}".encode()
        n += 1
    return token, bytes(body[:size])


def _jpeg(token: str):
    try:
        from PIL import Image
    except Exception:
        return None
    img = Image.new("RGB", (96, 64))
    px = img.load()
    for x in range(96):
        for y in range(64):
            px[x, y] = ((x * 5) % 256, (y * 7) % 256, (x * y) % 256)
    out = io.BytesIO()
    img.save(out, "JPEG", quality=85)
    jpg = out.getvalue()
    note = token.encode()
    return jpg[:2] + b"\xff\xfe" + struct.pack(">H", len(note) + 2) + note + jpg[2:]


def _save(name: str, raw: bytes, truth: dict, survival: str = "scan") -> None:
    """Write an image and its truth file.

    Survival is found by searching the raw image for each token, except where
    the generator never erases anything. There some content is compressed, so
    a plain search would miss it, and survival is known to be complete anyway.
    """
    SAMPLES.mkdir(parents=True, exist_ok=True)
    (SAMPLES / name).write_bytes(raw)
    truth["survival"] = survival
    for item in truth["items"]:
        item["survives"] = True if survival == "all" else raw.find(item["token"].encode()) != -1
    (SAMPLES / f"{name}.truth.json").write_text(json.dumps(truth, indent=2))
    gone = sum(1 for i in truth["items"] if not i["survives"])
    print(f"wrote {name:20} {len(raw):>9,} bytes  {len(truth['items'])} versions, {gone} already erased")


def make_littlefs() -> None:
    from littlefs import LittleFS

    t = Tracker("LDEMO", 7)
    fs = LittleFS(**LFS_CONFIG)
    fs.mkdir("/cam")
    fs.mkdir("/firmware")

    def put(path: str, token: str, data: bytes) -> None:
        with fs.open(path, "wb") as fh:
            fh.write(data)
        t.wrote(path, token, data)

    put("/config.ini", *_text(t, "device=camera01 admin_password=Sup3rSecret! api_key=AKIA_TEST_9931"))
    put("/log.txt", *_text(t, "boot ok, user alice logged in from 10.0.0.23"))
    put("/token.txt", *_text(t, "SESSION_TOKEN=abcdef0123456789"))
    put("/firmware/update.bin", *_long(t, "firmware image v1.4.2", 5000))
    t.counter += 1
    token = f"RVN-{t.prefix}-{t.counter:05d}"
    jpg = _jpeg(token)
    if jpg:
        put("/cam/snap_0001.jpg", token, jpg)
    put("/log.txt", *_text(t, "boot ok v2, no active sessions"))
    fs.remove("/token.txt")
    t.deleted("/token.txt")
    if jpg:
        fs.remove("/cam/snap_0001.jpg")
        t.deleted("/cam/snap_0001.jpg")
    raw = bytes(fs.context.buffer)
    _save("littlefs_demo.img", raw, t.truth("littlefs_demo.img", "littlefs",
                                             "littlefs-python reference implementation", config=LFS_CONFIG))


def make_jffs2() -> None:
    t = Tracker("JDEMO", 11)
    w = JFFS2Writer()
    logs = w.mkdir(1, "logs")

    ino = w.new_ino()
    tok, data = _text(t, "OLD VERSION api_secret=alpha-7731")
    w.write_file(ino, data)
    w.dirent(1, ino, "secret.txt")
    t.wrote("/secret.txt", tok, data)
    old = list(w.nodes[ino])
    w.truncate(ino)
    tok, data = _text(t, "NEW VERSION api_secret=bravo-2209")
    w.write_file(ino, data)
    t.wrote("/secret.txt", tok, data)
    for off in old:
        w.mark_obsolete(off)  # the kernel marks superseded nodes this way on NOR flash

    ino = w.new_ino()
    tok, data = _text(t, "DELETE_ME sensitive token XYZ789")
    w.write_file(ino, data)
    w.dirent(1, ino, "todelete.txt")
    t.wrote("/todelete.txt", tok, data)
    w.dirent(1, 0, "todelete.txt", dtype=0)
    t.deleted("/todelete.txt")

    ino = w.new_ino()
    t.counter += 1
    tok = f"RVN-{t.prefix}-{t.counter:05d}"
    data = (f"# {tok} device key\n-----BEGIN PRIVATE KEY-----\n"
            "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAq7BFUpkGp3+LQmlQ\n"
            "-----END PRIVATE KEY-----\n").encode()
    w.write_file(ino, data)
    w.dirent(1, ino, "keys.pem")
    t.wrote("/keys.pem", tok, data)

    ino = w.new_ino()
    tok, data = _text(t, "boot ok, user alice logged in from 10.0.0.23")
    w.write_file(ino, data)
    w.dirent(logs, ino, "boot.log")
    t.wrote("/logs/boot.log", tok, data)
    w.truncate(ino)
    tok, data = _text(t, "boot ok v2")
    w.write_file(ino, data)
    t.wrote("/logs/boot.log", tok, data)

    ino = w.new_ino()
    tok, data = _long(t, "sensor readings", 9000)
    w.write_file(ino, data, compress=True)
    w.dirent(logs, ino, "readings.csv")
    t.wrote("/logs/readings.csv", tok, data)
    _save("jffs2_demo.img", w.image(), t.truth("jffs2_demo.img", "jffs2",
                                               "hand written nodes with kernel CRCs, no garbage collection"), survival="all")


def make_ubifs() -> None:
    t = Tracker("UDEMO", 13)
    w = UBIFSWriter()
    w.ino(1, 0, nlink=2, mode=0o040755)
    tok, data = _text(t, '{"ssid": "FieldUnit", "psk": "hunter2hunter2"}')
    w.ino(65, len(data))
    w.data(65, 0, data)
    w.dent(1, "config.json", 65)
    t.wrote("/config.json", tok, data)

    tok, data = _text(t, "first secret alpha-5512")
    w.ino(66, len(data))
    w.data(66, 0, data)
    w.dent(1, "secret.txt", 66)
    t.wrote("/secret.txt", tok, data)
    tok, data = _text(t, "second secret bravo-8823")
    w.data(66, 0, data, compress=True)
    w.ino(66, len(data))
    t.wrote("/secret.txt", tok, data)

    tok, data = _long(t, "old event log", 3000)
    w.ino(67, len(data))
    w.data(67, 0, data)
    w.dent(1, "old.log", 67)
    t.wrote("/old.log", tok, data)
    w.dent(1, "old.log", 0)
    w.ino(67, len(data), nlink=0)
    t.deleted("/old.log")
    _save("ubifs_demo.img", w.image(), t.truth("ubifs_demo.img", "ubifs",
                                               "hand written nodes with kernel CRCs, parser check only"), survival="all")


def make_spiffs() -> None:
    sys.path.insert(0, str(ROOT / "tools" / "third_party"))
    import spiffsgen

    cfg = spiffsgen.SpiffsBuildConfig(256, 2, 4096, 2, 4, 32, 2, 2, True, True, "little", True, True, False)
    fs = spiffsgen.SpiffsFS(64 * 4096, cfg)
    t = Tracker("SDEMO", 17)
    files = [("/config.json", _text(t, '{"mqtt": "broker.local", "password": "Pa55w0rd-mqtt"}')),
             ("/secret.txt", _text(t, "OTA_SIGNING_KEY=5f2b9c77e1d04a88")),
             ("/www/index.html", _long(t, "<html>status page</html>", 1500)),
             ("/log.txt", _text(t, "wifi connected, rssi -61"))]
    ids = {}
    with tempfile.TemporaryDirectory() as tmp:
        for i, (name, (tok, data)) in enumerate(files):
            src = Path(tmp) / f"f{i}"
            src.write_bytes(data)
            ids[name] = fs.cur_obj_id
            fs.create_file(name, str(src))
            t.wrote(name, tok, data)
    raw = bytearray(fs.to_binary())

    # Delete one file the way SPIFFS does it. The deleted bit is cleared in each
    # page header and the page's lookup entry is set to zero, bytes stay put.
    target = ids["/secret.txt"]
    page, block = 256, 4096
    for bstart in range(0, len(raw), block):
        for p in range(1, block // page):
            off = bstart + p * page
            obj_id = struct.unpack_from("<H", raw, off)[0]
            if obj_id != 0xFFFF and (obj_id & 0x7FFF) == target:
                raw[off + 4] &= 0x7F
                struct.pack_into("<H", raw, bstart + (p - 1) * 2, 0)
    t.deleted("/secret.txt")
    _save("spiffs_demo.img", bytes(raw), t.truth("spiffs_demo.img", "spiffs",
                                                 "spiffsgen image with a SPIFFS style deletion applied"))


def main() -> int:
    print("Building labelled demo images in", SAMPLES)
    make_littlefs()
    make_jffs2()
    make_ubifs()
    make_spiffs()
    print("Each image has a matching .truth.json listing every version and its final state.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
