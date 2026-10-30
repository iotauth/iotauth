# Camera person-presence detector (HUMAN_PRESENCE)

Standalone OpenCV DNN (MobileNet-SSD) person detector. Captures one frame from
the Raspberry Pi camera and reports whether a person is present, as a line a C
endpoint can parse:

    PERSON present=<0|1> count=<n> confidence=<max, 3dp>

## Setup (Raspberry Pi)

    sudo apt-get install -y python3-opencv
    mkdir -p models && cd models
    curl -fsSLO https://raw.githubusercontent.com/djmv/MobilNet_SSD_opencv/master/MobileNetSSD_deploy.prototxt
    curl -fsSLO https://raw.githubusercontent.com/djmv/MobilNet_SSD_opencv/master/MobileNetSSD_deploy.caffemodel

## Use

    python3 detect.py --capture                 # capture + detect
    python3 detect.py --image frame.jpg         # run on an existing image
    python3 detect.py --capture --min-confidence 0.6
