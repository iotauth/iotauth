# YOLO Person Detection Entity

This folder contains the implementation for an IoT Auth entity that uses a YOLO model for person detection. 

## Table of Contents
- [Goal](#goal)
- [YOLO Library Research](#yolo-library-research)
- [Architecture](#architecture)
- [Setup](#setup)
- [Usage](#usage)

## Goal
The entity will:
1. Run a YOLO model (e.g., using OpenCV or Ultralytics) to process a video stream.
2. Detect persons in the stream.
3. Based on specific criteria (e.g., a person is detected for a certain amount of time or within a certain region), trigger a session key request from the IoT Auth server.
4. Use the session key for secure communication as needed.

## YOLO Library Research

To implement the YOLO person detection entity, we need a reliable Python library to run the model inference. This section compares the most viable options for our use case.

### 1. Ultralytics (YOLOv8 / YOLOv11)

Ultralytics provides the official, state-of-the-art implementation for the latest YOLO models.

**Pros:**
- **Extremely Simple API:** Inference takes just two lines of code:
  ```python
  from ultralytics import YOLO
  model = YOLO('yolov8n.pt')
  results = model(frame)
  ```
- **Built-in Utilities:** Built-in functions for drawing bounding boxes, object tracking, and handling video streams.
- **Accuracy & Speed:** Offers the best trade-off between speed and accuracy.

**Cons:**
- **Heavy Dependencies:** Requires installing `torch` and `torchvision`, which can be quite large.

### 2. OpenCV DNN Module

OpenCV has a deep neural network (DNN) module that can load and run pre-trained YOLO models.

**Pros:**
- **Lightweight:** Only requires `opencv-python`. We will likely need OpenCV anyway just to capture the webcam feed, so this adds **zero** extra dependencies.
- **CPU Optimized:** OpenCV's DNN module is heavily optimized for CPU inference out of the box.

**Cons:**
- **Verbose Code:** You have to write manual code to parse the raw network output tensors, filter by confidence, and apply non-maximum suppression (NMS).
- **Setup:** Requires manually downloading the model configuration and weights files.

### 3. PyTorch Hub (YOLOv5)

You can load YOLOv5 directly from PyTorch hub.

**Pros:**
- Widely used and very stable.

**Cons:**
- Requires the heavy `torch` dependency.
- Has largely been superseded by YOLOv8/YOLOv11 via the Ultralytics package.

### Hardware Acceleration & Cross-Platform Support (YOLOv8)

Because YOLOv8 (Ultralytics) runs on PyTorch, it automatically inherits excellent hardware acceleration across different operating systems:

* **Mac (Apple Silicon):** Native support for Apple's Metal Performance Shaders (MPS). By specifying `device='mps'`, inference is offloaded to the Mac GPU, enabling very fast real-time processing.
* **Windows (with NVIDIA GPU):** Fully supports CUDA. By specifying `device=0`, it utilizes NVIDIA CUDA cores for maximum performance.
* **Windows (CPU only):** Gracefully falls back to the CPU (`device='cpu'`). The YOLOv8 "nano" model (`yolov8n.pt`) is optimized enough to still achieve real-time frame rates (20-30+ FPS) on modern CPUs without a dedicated graphics card.

**Final Selection:**
Based on the lack of disk space constraints and the need for seamless, cross-platform hardware acceleration (Mac GPU, Windows CUDA, and CPU fallback), **Ultralytics YOLOv8** has been selected as the official library for this entity.

## Architecture

The main Python script (`yolo_client.py`) will be structured into modular, object-oriented classes:

1. **`HardwareDetector` (Helper)**
   - Includes a function to automatically detect the best available hardware using PyTorch.
   - On Mac, it selects Apple's Metal Performance Shaders (`mps`).
   - On Windows with an NVIDIA GPU, it selects `cuda`.
   - Otherwise, it falls back to `cpu`.

2. **`PersonDetector` (Class)**
   - Initializes the YOLOv8 model (`yolov8n.pt`) with the device selected by the `HardwareDetector`.
   - Connects to the webcam or video stream.
   - Processes frames to detect persons and tracks when specific detection criteria are met (e.g., confidence thresholds, consecutive frames).

3. **`AuthCommunicator` (Class)**
   - Utilizes the `iotauth` Python package (`IoTAuthContext`).
   - Called by the `PersonDetector` to request a session key (`ctx.request_session_keys()`) once a person is successfully detected according to the criteria.

4. **Main Loop**
   - Coordinates the detector and the communicator.

## Setup

To run the YOLOv8 person detection entity, you will need to set up a Python virtual environment and install the required dependencies.

1. **Navigate to the entity folder:**
   ```bash
   cd entity/yolo_entity
   ```

2. **Create a Python virtual environment:**
   ```bash
   python3 -m venv .venv
   ```

3. **Activate the virtual environment:**
   - On macOS/Linux: `source .venv/bin/activate`
   - On Windows: `.venv\Scripts\activate`

4. **Install the dependencies:**
   Install the required packages from `requirements.txt` (this includes `ultralytics` for YOLOv8 inference and `opencv-python` for capturing and rendering video streams).
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: The `ultralytics` package automatically installs PyTorch and other required ML dependencies).*

## Usage
(To be filled in later once the script is written)
