import cv2
import torch
import argparse
import datetime
import json
from ultralytics import YOLO
import os
import pathlib

# Import iotauth if available
try:
    from iotauth.context import IoTAuthContext
    from iotauth.secure_channel import session_key_is_expired
except ImportError:
    IoTAuthContext = None
    session_key_is_expired = None
    print("Warning: iotauth package not found in current environment.")


class AuthCommunicator:
    """Class to handle communication with the IoT Auth Server."""
    def __init__(self, config_path):
        self.mock_mode = IoTAuthContext is None or not config_path
        if self.mock_mode:
            print("AuthCommunicator: Running in MOCK mode (No config path provided or iotauth missing).")
            self.ctx = None
        else:
            print(f"AuthCommunicator: Initializing IoTAuthContext with config: {config_path}")

            abs_config_path = pathlib.Path(config_path).resolve()
            original_cwd = os.getcwd()
            
            # The iotauth library strictly resolves relative paths in the config based on CWD.
            # If the user provides a node example config, it expects CWD to be `example_entities/`.
            expected_anchor = abs_config_path.parent.parent.parent
            if expected_anchor.name == 'example_entities':
                print(f" -> Automatically adjusting CWD to '{expected_anchor.name}' for path resolution.")
                os.chdir(expected_anchor)
                
            try:
                self.ctx = IoTAuthContext.from_config(str(abs_config_path))
            finally:
                os.chdir(original_cwd)

    def trigger_session_key_request(self, people_count):
        """Requests a session key with the current context."""
        print(f"\n[EVENT] Triggering Session Key Request! Context: {{'Number of People': {people_count}}}")
        
        if self.mock_mode:
            print(" -> [MOCK] Session key request skipped.")
            return

        # Check if we already have a valid session key for the Servers group
        valid_key_found = False
        for key in self.ctx.session_keys.values():
            if not session_key_is_expired(key):
                try:
                    purpose_dict = json.loads(key.purpose)
                    if purpose_dict.get("group") == "Servers":
                        valid_key_found = True
                        break
                except Exception:
                    pass
        
        if valid_key_found:
            print(" -> A valid session key for 'Servers' already exists in cache. Skipping request to save network bandwidth!")
            return

        # Get current time in HH:MM format
        current_time = datetime.datetime.now().strftime("%H:%M")
        
        purpose_payload = {
            "group": "Servers", # The default target group in default.graph
            "context": {
                "Number of People": people_count,
                "Location": "Classroom",
                "Time of Day": current_time
            }
        }
        
        try:
            print(" -> Requesting session keys from Auth Server...")
            keys = self.ctx.request_session_keys(purpose=purpose_payload)
            print(f" -> Success! Received {len(keys)} session key(s).")
            for i, key in enumerate(keys):
                print(f"    Key {i+1} ID: {key.id}")
            # For now, we just receive the keys and discard them
        except Exception as e:
            print(f" -> Error requesting session keys: {e}")


class HardwareDetector:
    """Helper class to detect the optimal hardware acceleration device."""
    @staticmethod
    def get_optimal_device():
        if torch.cuda.is_available():
            print("Hardware Detection: NVIDIA GPU (CUDA) found.")
            return "cuda"
        elif torch.backends.mps.is_available():
            print("Hardware Detection: Mac GPU (MPS) found.")
            return "mps"
        else:
            print("Hardware Detection: No GPU found. Falling back to CPU.")
            return "cpu"


class PersonDetector:
    """Class to handle YOLO model loading and person detection logic."""
    def __init__(self, auth_communicator):
        self.device = HardwareDetector.get_optimal_device()
        print(f"Initializing YOLO model on device: {self.device}...")
        
        # Load the nano model for high speed
        self.model = YOLO('yolov8n.pt')
        
        # The 'person' class ID in the COCO dataset is 0
        self.PERSON_CLASS_ID = 0
        
        self.auth_communicator = auth_communicator
        
        # Track the number of people to detect when someone enters the frame
        self.previous_people_count = 0

    def process_frame(self, frame):
        """Runs inference on a single frame and tracks detection state."""
        # classes=[0] filters to only show persons. conf=0.90 enforces 90%+ confidence threshold
        results = self.model(frame, device=self.device, classes=[self.PERSON_CLASS_ID], conf=0.90, verbose=False)
        
        # The results list contains one Result object per image (we only passed 1 frame)
        result = results[0]
        
        current_people_count = len(result.boxes)
        
        # Trigger an event if a NEW person enters the frame
        if current_people_count > self.previous_people_count:
            print(f"\n[ALERT] Person count increased from {self.previous_people_count} to {current_people_count}!")
            self.auth_communicator.trigger_session_key_request(current_people_count)
            
        self.previous_people_count = current_people_count
            
        # Draw the bounding boxes on the frame for visualization
        annotated_frame = result.plot()
        return annotated_frame


def main():
    # get config file from arguments
    parser = argparse.ArgumentParser(description="YOLO Person Detection IoT Auth Client")
    parser.add_argument('--config', type=str, help='Path to the entity .config file', default=None)
    args = parser.parse_args()

    print("Starting YOLO Person Detection Client...")
    
    # Initialize our communicator and detector
    auth_comm = AuthCommunicator(config_path=args.config)
    detector = PersonDetector(auth_communicator=auth_comm)
    
    # Open default webcam (index 0)
    print("Opening webcam...")
    cap = cv2.VideoCapture(0)
    
    if not cap.isOpened():
        print("Error: Could not open webcam.")
        return

    print("Webcam opened. Press 'q' to quit.")
    
    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                print("Error: Failed to read frame from webcam.")
                break
                
            # Process the frame and detect persons
            annotated_frame = detector.process_frame(frame)
            
            # Display the resulting frame
            cv2.imshow('YOLOv8 Person Detection', annotated_frame)
            
            # Break the loop if 'q' is pressed
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
                
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        # Clean up
        cap.release()
        cv2.destroyAllWindows()
        print("Client shut down safely.")

if __name__ == "__main__":
    main()
