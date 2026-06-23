import cv2
import torch
import argparse
import datetime
import json
import time
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
        self.active_secure_channel = None
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

    def close(self):
        if self.active_secure_channel:
            try:
                self.active_secure_channel.close()
                print(" -> Secure channel closed gracefully.")
            except Exception:
                pass

    def send_secure_message(self, payload, purpose_context):
        """Sends a secure message, reusing or requesting a session key."""
        
        if self.mock_mode:
            print(" -> [MOCK] Secure message skipped.")
            return

        # Check if we have an active, valid channel
        if self.active_secure_channel and not self.active_secure_channel.closed:
            if not session_key_is_expired(self.active_secure_channel.session_key):
                # We have a valid connection, use it!
                self._send_message(payload)
                return
            else:
                print(" -> Active session key expired. Closing channel and fetching new key.")
                self.active_secure_channel.close()
                self.active_secure_channel = None

        active_session_key = None

        # Check if we already have any valid session key
        # (Since we only ever request keys for 'Servers', any valid key in cache is for 'Servers')
        for key in self.ctx.session_keys.values():
            if not session_key_is_expired(key):
                active_session_key = key
                break
        
        if active_session_key:
            print(" -> A valid session key for 'Servers' already exists in cache. Skipping Auth request!")
        else:
            try:
                print(" -> Requesting session keys from Auth Server...")
                keys = self.ctx.request_session_keys(purpose=purpose_context)
                print(f" -> Success! Received {len(keys)} session key(s).")
                for i, key in enumerate(keys):
                    print(f"    Key {i+1} ID: {key.id}")
                if keys:
                    active_session_key = keys[0]
            except Exception as e:
                print(f" -> Error requesting session keys: {e}")
                return

        if not active_session_key:
            print(" -> Failed to obtain a valid session key. Cannot send alert.")
            return
            
        # Establish a new persistent secure connection to the Python Server
        try:
            print(" -> Establishing secure connection to Python Server at 127.0.0.1:21100...")
            self.active_secure_channel = self.ctx.connect_secure(
                key=active_session_key, 
                host='127.0.0.1', 
                port=21100
            )
            print(" -> Secure channel established! Connection is now persistent.")
            self._send_message(payload)
        except Exception as e:
            print(f" -> Error communicating with Server: {e}")
            self.active_secure_channel = None

    def _send_message(self, payload):
        try:
            self.active_secure_channel.send(payload)
            try:
                print(f" -> Sent message securely: {payload.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f" -> Sent message securely: {len(payload)} bytes")
        except Exception as e:
            print(f" -> Failed to send message: {e}")
            self.active_secure_channel.close()
            self.active_secure_channel = None


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
        results = self.model(frame, device=self.device, classes=[self.PERSON_CLASS_ID], conf=0.70, verbose=False)
        
        # The results list contains one Result object per image (we only passed 1 frame)
        result = results[0]
        
        current_people_count = len(result.boxes)
        
        # Trigger an event if a NEW person enters the frame
        if current_people_count > self.previous_people_count:
            print(f"\n[EVENT] Triggering Detection Alert! Context: {{'Number of People': {current_people_count}}}")
            
            current_time = datetime.datetime.now().strftime("%H:%M")
            purpose_payload = {
                "group": "Servers",
                "context": {
                    "Number of People": current_people_count,
                    "Location": "Classroom",
                    "Time of Day": current_time
                }
            }
            alert_bytes = f"Alert: Person detected! Total count: {current_people_count}".encode('utf-8')
            
            self.auth_communicator.send_secure_message(alert_bytes, purpose_payload)
            
        self.previous_people_count = current_people_count
            
        # Draw the bounding boxes on the frame for visualization
        annotated_frame = result.plot()
        return annotated_frame


def main():
    # get config file from arguments
    parser = argparse.ArgumentParser(description="YOLO Person Detection IoT Auth Client")
    parser.add_argument('--config', type=str, help='Path to the entity .config file', default=None)
    parser.add_argument('--test', action='store_true', help='Run a simulated test for expiration policies without using webcam')
    args = parser.parse_args()

    print("Starting YOLO Person Detection Client...")
    
    # Initialize our communicator
    auth_comm = AuthCommunicator(config_path=args.config)
    
    if args.test:
        print("Running in TEST mode to verify key expiration policies...")
        
        def simulate_alert(count):
            print(f"\n[EVENT] Triggering Simulated Detection Alert! Context: {{'Number of People': {count}}}")
            current_time = datetime.datetime.now().strftime("%H:%M")
            purpose_payload = {
                "group": "Servers",
                "context": {
                    "Number of People": count,
                    "Location": "Classroom",
                    "Time of Day": current_time
                }
            }
            alert_bytes = f"Alert: Person detected! Total count: {count}".encode('utf-8')
            auth_comm.send_secure_message(alert_bytes, purpose_payload)
            
        print("\n--- TEST PHASE 1: Fetch Key 1 and Wait for Absolute Expiration (2 min policy) ---")
        simulate_alert(1)  # Fetches Key 1
        
        print("\n--- TEST PHASE 2: Waiting 125 seconds... ---")
        for i in range(125, 0, -5):
            print(f"Waiting... {i} seconds left")
            time.sleep(5)
            
        print("\n--- TEST PHASE 3: Detection after Absolute Expiration (Should fetch Key 2) ---")
        simulate_alert(1)
        
        print("\n--- TEST PHASE 4: Waiting 30 seconds... ---")
        for i in range(30, 0, -5):
            print(f"Waiting... {i} seconds left")
            time.sleep(5)
            
        print("\n--- TEST PHASE 5: Detection before Relative Expiration (Should reuse Key 2) ---")
        simulate_alert(1)
        
        print("\n--- TEST PHASE 6: Waiting 35 seconds to hit Relative Expiration (1 min policy) ---")
        for i in range(35, 0, -5):
            print(f"Waiting... {i} seconds left")
            time.sleep(5)
            
        print("\n--- TEST PHASE 7: Detection after Relative Expiration (Should fetch Key 3) ---")
        simulate_alert(1)
        
        auth_comm.close()
        print("Test mode completed successfully.")
        return

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
        auth_comm.close()
        cap.release()
        cv2.destroyAllWindows()
        print("Client shut down safely.")

if __name__ == "__main__":
    main()
