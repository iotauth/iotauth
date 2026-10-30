#!/usr/bin/env python3
"""Standalone camera person-presence detector (OpenCV DNN, MobileNet-SSD).

Captures one frame from the Raspberry Pi camera (rpicam-jpeg) or reads a given
image, runs a MobileNet-SSD person detector on the CPU, and prints one result
line plus a JSON object. Meant to back a HUMAN_PRESENCE local check: the C
endpoint invokes it and reads the result line.

Result line (easy to parse from C):
    PERSON present=<0|1> count=<n> confidence=<max, 3dp>
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

import cv2

# MobileNet-SSD was trained on PASCAL VOC; class 15 is "person".
PERSON_CLASS_ID = 15
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROTO = os.path.join(HERE, "models", "MobileNetSSD_deploy.prototxt")
DEFAULT_MODEL = os.path.join(HERE, "models", "MobileNetSSD_deploy.caffemodel")


def capture_frame(width, height):
    """Capture one JPEG from the Pi camera, returning its file path."""
    fd, path = tempfile.mkstemp(suffix=".jpg", prefix="human_presence_")
    os.close(fd)
    subprocess.run(
        ["rpicam-jpeg", "-n", "-o", path, "-t", "500",
         "--width", str(width), "--height", str(height)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return path


def detect_people(image_path, proto, model, min_confidence):
    """Return (count, max_confidence) of person detections above threshold."""
    img = cv2.imread(image_path)
    if img is None:
        raise RuntimeError("could not read image: " + image_path)
    h, w = img.shape[:2]
    net = cv2.dnn.readNetFromCaffe(proto, model)
    blob = cv2.dnn.blobFromImage(
        cv2.resize(img, (300, 300)), 0.007843, (300, 300), 127.5)
    net.setInput(blob)
    detections = net.forward()
    count, best = 0, 0.0
    for i in range(detections.shape[2]):
        confidence = float(detections[0, 0, i, 2])
        class_id = int(detections[0, 0, i, 1])
        if class_id == PERSON_CLASS_ID and confidence >= min_confidence:
            count += 1
            best = max(best, confidence)
    return count, best


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--capture", action="store_true",
                     help="capture one frame from the Pi camera")
    src.add_argument("--image", help="run on this image file instead")
    ap.add_argument("--min-confidence", type=float, default=0.5)
    ap.add_argument("--proto", default=DEFAULT_PROTO)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--width", type=int, default=1280)
    ap.add_argument("--height", type=int, default=720)
    args = ap.parse_args()

    captured = None
    try:
        image_path = args.image
        if args.capture:
            image_path = captured = capture_frame(args.width, args.height)
        count, best = detect_people(image_path, args.proto, args.model,
                                    args.min_confidence)
    finally:
        if captured and os.path.exists(captured):
            os.remove(captured)

    present = 1 if count > 0 else 0
    print("PERSON present=%d count=%d confidence=%.3f" % (present, count, best))
    print(json.dumps({"present": bool(present), "count": count,
                      "confidence": round(best, 3),
                      "min_confidence": args.min_confidence}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
