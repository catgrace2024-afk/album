#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
会社で見る写真アルバム ビルダー

使い方:
    python3 build.py

やること:
  1. SRC フォルダの写真を読む（新しいものが先頭）
  2. sips で縮小（一覧用 480px / 拡大用 1800px）して JPEG に統一
  3. パスワードから鍵を作り、AES-256-CTR + HMAC-SHA256 で1枚ずつ暗号化
  4. docs/ に書き出す（GitHub Pages で配信するのはこのフォルダ）

docs/ に入るのは暗号化されたファイルだけ。ファイル名も中身も、
パスワードを知らない人には写真かどうかさえ分からない。
"""
import ctypes, hashlib, hmac, json, os, re, secrets, shutil, subprocess, sys, tempfile, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get("PV_SRC") or os.path.expanduser("~/Pictures/会社で見る写真")
DOCS = os.path.join(HERE, "docs")
DATA = os.path.join(DOCS, "d")
PWFILE = os.environ.get("PV_PW") or os.path.join(HERE, ".password")

ITERS = 300000
THUMB_PX, THUMB_Q = 480, 62
FULL_PX, FULL_Q = 1800, 74
EXTS = (".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp", ".tif", ".tiff", ".gif", ".bmp")
VERIFY_MSG = b"photo-vault-verify"

# ---------- AES-256-CTR (macOS CommonCrypto 経由。鍵をコマンド行に出さない) ----------
_lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
_create = _lib.CCCryptorCreateWithMode
_create.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_uint32,
                    ctypes.POINTER(ctypes.c_void_p)]
_create.restype = ctypes.c_int32
_update = _lib.CCCryptorUpdate
_update.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                    ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
_update.restype = ctypes.c_int32
_release = _lib.CCCryptorRelease
_release.argtypes = [ctypes.c_void_p]
_release.restype = ctypes.c_int32


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    ref = ctypes.c_void_p()
    st = _create(0, 4, 0, 0, iv, key, len(key), None, 0, 0, 2, ctypes.byref(ref))
    if st != 0:
        raise RuntimeError("暗号化の初期化に失敗 (%d)" % st)
    out = ctypes.create_string_buffer(len(data))
    moved = ctypes.c_size_t(0)
    st = _update(ref, data, len(data), out, len(data), ctypes.byref(moved))
    _release(ref)
    if st != 0:
        raise RuntimeError("暗号化に失敗 (%d)" % st)
    return out.raw[:moved.value]


def seal(blob: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    """[16バイトIV][32バイトHMAC][本体] の形にまとめる"""
    iv = secrets.token_bytes(16)
    ct = aes_ctr(enc_key, iv, blob)
    tag = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return iv + tag + ct


# ---------- 画像処理 ----------
def sips_size(path):
    out = subprocess.run(["sips", "-g", "pixelWidth", "-g", "pixelHeight", path],
                         capture_output=True, text=True).stdout
    w = re.search(r"pixelWidth:\s*(\d+)", out)
    h = re.search(r"pixelHeight:\s*(\d+)", out)
    return (int(w.group(1)), int(h.group(1))) if w and h else (0, 0)


def make_jpeg(src, dst, max_px, quality):
    w, h = sips_size(src)
    cmd = ["sips", "-s", "format", "jpeg", "-s", "formatOptions", str(quality)]
    if max(w, h) > max_px:                      # 元より大きくはしない
        cmd += ["-Z", str(max_px)]
    cmd += [src, "--out", dst]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(dst):
        raise RuntimeError(r.stderr.strip() or "sips が失敗")
    return sips_size(dst)


# ---------- 本体 ----------
def main():
    if not os.path.isfile(PWFILE):
        sys.exit("パスワードが設定されていません。先に set-password.command を実行してください。")
    with open(PWFILE, "rb") as f:
        pw = f.read().rstrip(b"\r\n")
    if len(pw) < 4:
        sys.exit("パスワードが短すぎます。set-password.command でやり直してください。")

    if not os.path.isdir(SRC):
        sys.exit("写真フォルダが見つかりません: " + SRC)
    files = [os.path.join(SRC, n) for n in os.listdir(SRC)
             if n.lower().endswith(EXTS) and not n.startswith(".")]
    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)   # 新しいものが先頭
    if not files:
        sys.exit("写真が1枚もありません。%s に写真を入れてください。" % SRC)

    # 鍵を作る（塩は毎回作り直す＝パスワードを変えてもそのまま通る）
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw, salt, ITERS, dklen=64)
    enc_key, mac_key = dk[:32], dk[32:]
    verifier = hmac.new(mac_key, VERIFY_MSG, hashlib.sha256).hexdigest()

    # 出力先をきれいにする
    if os.path.isdir(DATA):
        shutil.rmtree(DATA)
    os.makedirs(DATA)

    items = []
    tmp = tempfile.mkdtemp(prefix="pv-")
    total = 0
    try:
        for i, path in enumerate(files, 1):
            name = os.path.splitext(os.path.basename(path))[0]
            print("[%d/%d] %s" % (i, len(files), os.path.basename(path)))
            try:
                tj = os.path.join(tmp, "t.jpg")
                fj = os.path.join(tmp, "f.jpg")
                make_jpeg(path, tj, THUMB_PX, THUMB_Q)
                fw, fh = make_jpeg(path, fj, FULL_PX, FULL_Q)
            except Exception as e:
                print("    → 読めなかったので飛ばします (%s)" % e)
                continue

            entry = {}
            for key, jp in (("t", tj), ("f", fj)):
                with open(jp, "rb") as f:
                    blob = f.read()
                binname = secrets.token_hex(8) + ".bin"
                sealed = seal(blob, enc_key, mac_key)
                with open(os.path.join(DATA, binname), "wb") as g:
                    g.write(sealed)
                entry[key] = binname
                total += len(sealed)
            mt = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            entry["n"] = name
            entry["d"] = mt.strftime("%Y/%m/%d")
            entry["w"], entry["h"] = fw, fh
            items.append(entry)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if not items:
        sys.exit("1枚も処理できませんでした。")

    # 一覧（名前・日付も含む）も暗号化して置く
    manifest = json.dumps({"items": items}, ensure_ascii=False).encode("utf-8")
    with open(os.path.join(DOCS, "manifest.bin"), "wb") as f:
        f.write(seal(manifest, enc_key, mac_key))

    meta = {"v": 1, "salt": salt.hex(), "iters": ITERS, "verify": verifier,
            "built": datetime.datetime.now().strftime("%Y/%m/%d %H:%M"),
            "count": len(items)}
    with open(os.path.join(DOCS, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)

    print("\n完成: %d枚 / 合計 %.1f MB" % (len(items), total / 1048576.0))
    print("次は『アップロードして』と伝えてください。")


if __name__ == "__main__":
    main()
