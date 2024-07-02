import cv2
import numpy as np


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
