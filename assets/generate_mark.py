#!/usr/bin/env python3
"""Generates the HankoXml seal mark.

A hanko is a carved personal seal, so the mark is drawn the way a real one
prints: a hand-cut square frame with two chevrons inside, in seal-ink
vermilion (shubun / positive carving -- red strokes, paper showing through).

Every shape is emitted as a single fill-rule="evenodd" <path> of outlined
strokes. There are no stroke attributes, no <style> and no <mask>, so one file
renders identically through GitHub's SVG sanitizer, browser favicon pipelines
and ICO conversion.

Usage:
    python3 assets/generate_mark.py assets/hanko-mark.svg
    python3 assets/generate_mark.py assets/hanko-mark-compact.svg --compact
"""
import math
import random
import sys

INK = "#C8322A"
CX = CY = 64.0


# --- stroke -> outline (square caps, miter joins) -------------------------
def _unit(a, b):
    dx, dy = b[0] - a[0], b[1] - a[1]
    length = math.hypot(dx, dy)
    return dx / length, dy / length


def _intersect(p1, p2, p3, p4):
    (x1, y1), (x2, y2), (x3, y3), (x4, y4) = p1, p2, p3, p4
    den = (x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4)
    if abs(den) < 1e-9:
        return p2
    a = x1 * y2 - y1 * x2
    b = x3 * y4 - y3 * x4
    return ((a * (x3 - x4) - (x1 - x2) * b) / den,
            (a * (y3 - y4) - (y1 - y2) * b) / den)


def _offset(pts, d):
    segs = []
    for a, b in zip(pts, pts[1:]):
        ux, uy = _unit(a, b)
        nx, ny = -uy, ux
        segs.append(((a[0] + nx * d, a[1] + ny * d),
                     (b[0] + nx * d, b[1] + ny * d)))
    out = [segs[0][0]]
    for s1, s2 in zip(segs, segs[1:]):
        out.append(_intersect(s1[0], s1[1], s2[0], s2[1]))
    out.append(segs[-1][1])
    return out


def stroke_outline(pts, w):
    """Convert a polyline into a closed filled outline."""
    # Square caps: pre-extend both ends by w/2 along their terminal direction.
    ux, uy = _unit(pts[0], pts[1])
    pts = [(pts[0][0] - ux * w / 2, pts[0][1] - uy * w / 2)] + list(pts[1:])
    ux, uy = _unit(pts[-2], pts[-1])
    pts = list(pts[:-1]) + [(pts[-1][0] + ux * w / 2, pts[-1][1] + uy * w / 2)]
    ring = _offset(pts, w / 2) + list(reversed(_offset(pts, -w / 2)))
    return ("M%.2f %.2f" % ring[0]
            + "".join("L%.2f %.2f" % p for p in ring[1:]) + "Z")


# --- the carved frame -----------------------------------------------------
def squircle(a, e=12.0, amp=0.012, seed=7, n=48, reverse=False):
    """A superellipse with per-point jitter, smoothed through Catmull-Rom, so
    the edge wobbles the way a hand-cut seal bites into paper.

    `reverse` emits the contour with the opposite winding, which is how a hole
    is punched under fill-rule="nonzero"."""
    rnd = random.Random(seed)
    pts = []
    for i in range(n):
        t = 2 * math.pi * i / n
        ct, st = math.cos(t), math.sin(t)
        x = math.copysign(abs(ct) ** (2.0 / e), ct)
        y = math.copysign(abs(st) ** (2.0 / e), st)
        j = 1 + rnd.uniform(-amp, amp)
        pts.append((CX + a * x * j, CY + a * y * j))
    if reverse:
        pts.reverse()
    d = "M%.2f %.2f" % pts[0]
    for i in range(n):
        p0, p1 = pts[(i - 1) % n], pts[i]
        p2, p3 = pts[(i + 1) % n], pts[(i + 2) % n]
        c1 = (p1[0] + (p2[0] - p0[0]) / 6.0, p1[1] + (p2[1] - p0[1]) / 6.0)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6.0, p2[1] - (p3[1] - p1[1]) / 6.0)
        d += "C%.2f %.2f %.2f %.2f %.2f %.2f" % (c1 + c2 + p2)
    return d + "Z"


# Full size: hollow frame (outer contour + inner contour, hollowed by
# evenodd) with the chevrons floating inside it.
FRAME_OUTER, FRAME_INNER = 60.0, 52.0
CHEV_W = 10.0
CHEV_L = [(48, 40), (30, 64), (48, 88)]
CHEV_R = [(80, 40), (98, 64), (80, 88)]

# Small optical size (<= 32px): the hollow frame and the gap between the
# chevrons close into mud, so the seal inverts to a solid field with the
# chevrons knocked out of it.
CHEV_WC = 12.0
CHEV_LC = [(46, 40), (28, 64), (46, 88)]
CHEV_RC = [(82, 40), (100, 64), (82, 88)]


# Gem variant: the same seal, with a Ruby cut set between the brackets. The
# chevrons move outward to open up a centre field for it.
GEM_CHEV_W = 8.0
GEM_CHEV_L = [(37, 44), (24, 64), (37, 84)]
GEM_CHEV_R = [(91, 44), (104, 64), (91, 84)]

# Drawn as an outline plus facet lines, matching the positive-carving language
# of the frame. The contour starts mid-top-edge so the two square caps butt
# together along a straight run instead of notching a corner.
GEM_OUTLINE = [(64, 50), (73, 50), (81, 61), (64, 84), (47, 61), (55, 50), (64, 50)]
GEM_OUTLINE_W = 4.5
GEM_FACET_W = 2.4
GEM_FACETS = [
    [(47, 61), (81, 61)],        # girdle
    [(61, 50), (57.5, 61)],      # crown, left
    [(67, 50), (70.5, 61)],      # crown, right
    [(57.5, 61), (64, 83)],      # pavilion, left
    [(70.5, 61), (64, 83)],      # pavilion, right
]


def mark_svg(color=INK, compact=False):
    if compact:
        d = (squircle(63.0, amp=0.008, seed=7)
             + stroke_outline(CHEV_LC, CHEV_WC)
             + stroke_outline(CHEV_RC, CHEV_WC))
    else:
        d = (squircle(FRAME_OUTER, seed=7)
             + squircle(FRAME_INNER, seed=23)
             + stroke_outline(CHEV_L, CHEV_W)
             + stroke_outline(CHEV_R, CHEV_W))
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" '
            'role="img" aria-label="HankoXml">\n'
            '  <title>HankoXml</title>\n'
            f'  <path fill="{color}" fill-rule="evenodd" d="{d}"/>\n'
            '</svg>\n')


def gem_svg(color=INK):
    """Uses fill-rule="nonzero" rather than evenodd: the facet lines overlap
    the gem outline, and evenodd would XOR those overlaps into white notches.
    Under nonzero the frame is hollowed by winding the inner contour the other
    way, and every overlapping stroke simply unions."""
    d = (squircle(FRAME_OUTER, seed=7)
         + squircle(FRAME_INNER, seed=23, reverse=True)
         + stroke_outline(GEM_CHEV_L, GEM_CHEV_W)
         + stroke_outline(GEM_CHEV_R, GEM_CHEV_W)
         + stroke_outline(GEM_OUTLINE, GEM_OUTLINE_W)
         + "".join(stroke_outline(f, GEM_FACET_W) for f in GEM_FACETS))
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" '
            'role="img" aria-label="HankoXml">\n'
            '  <title>HankoXml</title>\n'
            f'  <path fill="{color}" fill-rule="nonzero" d="{d}"/>\n'
            '</svg>\n')


if __name__ == "__main__":
    out = sys.argv[1]
    if "--gem" in sys.argv:
        body = gem_svg()
    else:
        body = mark_svg(compact="--compact" in sys.argv)
    with open(out, "w") as fh:
        fh.write(body)
    print("wrote", out)
