"""
Generate capacitra.ico from the Capacitra brand mark.

Pure stdlib (no Pillow). Renders the hexagon + folder + 3 ascending bars
into multiple sizes (16, 32, 48, 64, 128, 256) and bundles them into a
Windows .ico file as PNG-encoded entries.

Run once before PyInstaller; build_exe.bat does this automatically.
"""
import math
import struct
import zlib


# ---------------- Tiny RGBA framebuffer renderer ----------------

class Canvas:
    """Minimal RGBA buffer with polygon fill, used to paint the icon."""
    def __init__(self, w, h):
        self.w = w
        self.h = h
        # transparent background
        self.px = bytearray(w * h * 4)

    def set(self, x, y, r, g, b, a=255):
        if 0 <= x < self.w and 0 <= y < self.h:
            i = (y * self.w + x) * 4
            self.px[i] = r
            self.px[i + 1] = g
            self.px[i + 2] = b
            self.px[i + 3] = a

    def fill_poly(self, pts, r, g, b, a=255):
        ys = [p[1] for p in pts]
        y_min = max(0, int(math.floor(min(ys))))
        y_max = min(self.h - 1, int(math.ceil(max(ys))))
        n = len(pts)
        for y in range(y_min, y_max + 1):
            xs = []
            for i in range(n):
                p1, p2 = pts[i], pts[(i + 1) % n]
                y1, y2 = p1[1], p2[1]
                if (y1 <= y < y2) or (y2 <= y < y1):
                    if y2 != y1:
                        x = p1[0] + (y - y1) * (p2[0] - p1[0]) / (y2 - y1)
                        xs.append(x)
            xs.sort()
            for i in range(0, len(xs) - 1, 2):
                x1 = int(math.floor(xs[i]))
                x2 = int(math.ceil(xs[i + 1]))
                for x in range(max(0, x1), min(self.w, x2 + 1)):
                    self.set(x, y, r, g, b, a)

    def fill_rect(self, x0, y0, w, h, r, g, b, a=255):
        for y in range(int(y0), int(y0 + h)):
            for x in range(int(x0), int(x0 + w)):
                self.set(x, y, r, g, b, a)

    def to_png(self):
        """Encode the canvas as a PNG byte string."""
        def chunk(tag, data):
            return (struct.pack(">I", len(data)) + tag + data
                    + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

        raw = bytearray()
        for y in range(self.h):
            raw.append(0)  # filter type: None
            raw.extend(self.px[y * self.w * 4:(y + 1) * self.w * 4])
        out = b"\x89PNG\r\n\x1a\n"
        out += chunk(b"IHDR",
                     struct.pack(">IIBBBBB", self.w, self.h, 8, 6, 0, 0, 0))
        out += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        out += chunk(b"IEND", b"")
        return out


# ---------------- Capacitra mark renderer ----------------

def hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def render_mark(size):
    """Render the Capacitra hex+folder+bars mark at the given size."""
    c = Canvas(size, size)
    s = size

    # Outer hex (navy)
    cx, cy, R = s / 2, s / 2, s * 0.45
    hex_outer = []
    for i in range(6):
        ang = math.radians(-90 + 60 * i)
        hex_outer.append((cx + R * math.cos(ang),
                          cy + R * math.sin(ang)))
    c.fill_poly(hex_outer, *hex_to_rgb("#1E3A8A"))

    # Inner hex (brighter blue)
    inset = max(2, int(s * 0.05))
    hex_inner = []
    for i in range(6):
        ang = math.radians(-90 + 60 * i)
        hex_inner.append((cx + (R - inset) * math.cos(ang),
                          cy + (R - inset) * math.sin(ang)))
    c.fill_poly(hex_inner, *hex_to_rgb("#1D4ED8"))

    # Folder body (cyan)
    fw = s * 0.56
    fh = s * 0.34
    fx = (s - fw) / 2
    fy = s / 2 - fh * 0.18
    tab_step = max(1, int(s * 0.045))
    folder = [
        (fx,             fy),
        (fx + fw * 0.45, fy),
        (fx + fw * 0.55, fy + tab_step),
        (fx + fw,        fy + tab_step),
        (fx + fw,        fy + fh),
        (fx,             fy + fh),
    ]
    c.fill_poly(folder, *hex_to_rgb("#0EA5E9"))

    # Three ascending bars (white)
    bw = fw / 6.5
    bx0 = fx + bw * 0.7
    by = fy + fh - max(1, int(s * 0.025))
    for i, frac in enumerate([0.35, 0.55, 0.80]):
        x = bx0 + i * bw * 1.55
        h_bar = fh * frac
        c.fill_rect(x, by - h_bar, bw, h_bar, 255, 255, 255)

    return c


# ---------------- ICO file writer ----------------

def write_ico(filename, sizes=(16, 32, 48, 64, 128, 256)):
    images = []
    for sz in sizes:
        canv = render_mark(sz)
        images.append((sz, canv.to_png()))

    # ICONDIR (6 bytes) + N x ICONDIRENTRY (16 bytes each)
    out = bytearray()
    out += struct.pack("<HHH", 0, 1, len(images))  # reserved, type=1 (icon), count
    offset = 6 + 16 * len(images)
    entries = []
    for sz, data in images:
        # width/height of 0 means 256 in the .ico header byte
        w_byte = 0 if sz == 256 else sz
        h_byte = 0 if sz == 256 else sz
        entries.append(struct.pack("<BBBBHHII",
                                   w_byte, h_byte, 0, 0, 1, 32,
                                   len(data), offset))
        offset += len(data)
    out += b"".join(entries)
    for _sz, data in images:
        out += data
    with open(filename, "wb") as f:
        f.write(bytes(out))
    print(f"Wrote {filename} ({len(out):,} bytes, {len(images)} sizes)")


if __name__ == "__main__":
    write_ico("capacitra.ico")
