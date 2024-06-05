import cv2
import numpy as np
from paddleocr import PaddleOCR

def zoom_image(image, zoom_factor):
    height, width = image.shape[:2]
    new_height, new_width = int(height * zoom_factor), int(width * zoom_factor)

    # Calculate the scaling factors in x and y direction
    fx = new_width / width
    fy = new_height / height

    # Perform the zoom
    zoomed_image = cv2.resize(image, None, fx=fx, fy=fy, interpolation=cv2.INTER_LINEAR)
    return zoomed_image

def enhance_brightness(image, brightness=1.3):
    # Convert the image to float32
    image_float = image.astype(float)
    # Multiply the image by the brightness factor
    image_bright = cv2.multiply(image_float, brightness)
    # Make sure the values are within the correct range
    image_bright = np.clip(image_bright, 0, 255)
    # Convert the image back to 8-bit
    image_bright = image_bright.astype(np.uint8)
    return image_bright

def increase_contrast(image):
    # Create a CLAHE object (Arguments are optional)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    contrast_image = clahe.apply(image)
    return contrast_image

async def process_file(file_contents):
    # Convert file contents to a numpy array and read the image
    np_arr = np.frombuffer(file_contents, np.uint8)
    input_image = cv2.imdecode(np_arr, cv2.IMREAD_GRAYSCALE)

    if input_image is None:
        return "Failed to decode image"

    # Enhance the brightness
    bright_image = enhance_brightness(input_image, 1.3)

    # Increase the contrast
    contrast_image = increase_contrast(bright_image)

    # Instantiate an OCR agent
    ocr_agent = PaddleOCR(lang='german', det_algorithm='DB')

    # Use the OCR agent to extract text from the image
    result = ocr_agent.ocr(contrast_image, cls=False)

    # Check if result is not None
    if result is not None:
        try:
            # Extract only the text from the result
            text_only = '\n'.join([word_info[-1][0] for line in result for word_info in line])
        except TypeError:
            text_only = "Error occurred while extracting text"
    else:
        text_only = "No text found in the image"

    # Store the result in Redis (assuming you have a function for this)
    return text_only
