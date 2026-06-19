import cv2
import torch
from ultralytics import YOLO

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
    def __init__(self):
        self.device = HardwareDetector.get_optimal_device()
        print(f"Initializing YOLO model on device: {self.device}...")
        
        # Load the nano model for high speed
        self.model = YOLO('yolov8n.pt')
        
        # The 'person' class ID in the COCO dataset is 0
        self.PERSON_CLASS_ID = 0
        
        # Detection criteria state
        self.consecutive_detections = 0
        self.DETECTION_THRESHOLD = 5  # Number of consecutive frames needed to trigger an event

    def process_frame(self, frame):
        """Runs inference on a single frame and tracks detection state."""
        # Run inference on the frame
        # classes=[0] filters the results to only show persons
        # verbose=False stops the console from being spammed with log lines for every single frame
        results = self.model(frame, device=self.device, classes=[self.PERSON_CLASS_ID], verbose=False)
        
        person_detected_in_frame = False
        
        # The results list contains one Result object per image (we only passed 1 frame)
        result = results[0]
        
        if len(result.boxes) > 0:
            person_detected_in_frame = True
            
        # Update consecutive detection state
        if person_detected_in_frame:
            self.consecutive_detections += 1
            if self.consecutive_detections == self.DETECTION_THRESHOLD:
                print("\n[EVENT] Person detected for multiple consecutive frames!")
                print(" -> (Future Step: Trigger IoT Auth Session Key Request Here)\n")
        else:
            self.consecutive_detections = 0
            
        # Draw the bounding boxes on the frame for visualization
        annotated_frame = result.plot()
        return annotated_frame

def main():
    print("Starting YOLO Person Detection Client...")
    detector = PersonDetector()
    
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
