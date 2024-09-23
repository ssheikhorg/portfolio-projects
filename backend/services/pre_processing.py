import cv2
import numpy as np
from fastapi import HTTPException

from api.process_file.processor import is_image


def zoom_image(image, zoom_factor):
    """
    Zooms into the image by a given factor.

    Parameters:
    image (ndarray): Input image.
    zoom_factor (float): Factor by which to zoom the image.

    Returns:
    ndarray: Zoomed image.
    """
    if not isinstance(image, np.ndarray):
        raise TypeError("Input image must be a numpy array.")
    if zoom_factor <= 0:
        raise ValueError("Zoom factor must be positive.")

    height, width = image.shape[:2]
    new_height, new_width = int(height * zoom_factor), int(width * zoom_factor)

    # Perform the zoom using resize function
    zoomed_image = cv2.resize(
        image, (new_width, new_height), interpolation=cv2.INTER_LINEAR
    )
    return zoomed_image


def enhance_brightness(image, brightness=1.3):
    """
    Enhances the brightness of the image.

    Parameters:
    image (ndarray): Input image.
    brightness (float): Factor by which to enhance brightness.

    Returns:
    ndarray: Brightness-enhanced image.
    """
    if not isinstance(image, np.ndarray):
        raise TypeError("Input image must be a numpy array.")
    if brightness <= 0:
        raise ValueError("Brightness factor must be positive.")

    # Use cv2.convertScaleAbs for efficiency
    image_bright = cv2.convertScaleAbs(image, alpha=brightness, beta=0)
    return image_bright


def determine_best_color_space(image):
    """
    Determines the best color space (LAB or YCrCb) to use for CLAHE based on image characteristics.

    Parameters:
    image (ndarray): Input color image.

    Returns:
    str: 'LAB' or 'YCrCb', indicating the best color space to use.
    """
    hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
    saturation = hsv[:, :, 1]
    mean_saturation = np.mean(saturation)

    return "YCrCb" if mean_saturation > 100 else "LAB"


def apply_clahe_to_channel(channel, clip_limit, tile_grid_size):
    clahe = cv2.createCLAHE(clipLimit=clip_limit, tileGridSize=tile_grid_size)
    return clahe.apply(channel)


def increase_contrast(image, clip_limit=2.0, tile_grid_size=(8, 8)):
    """
    Increases the contrast of the image using CLAHE.

    Parameters:
    image (ndarray): Input image (grayscale or color).
    clip_limit (float): Threshold for contrast limiting.
    tile_grid_size (tuple): Size of grid for histogram equalization.

    Returns:
    ndarray: Contrast-enhanced image.
    """
    if not isinstance(image, np.ndarray):
        raise TypeError("Input image must be a numpy array.")
    if (
        clip_limit <= 0
        or not isinstance(tile_grid_size, (tuple, list))
        or len(tile_grid_size) != 2
    ):
        raise ValueError("Invalid clip limit or tile grid size.")

    if len(image.shape) == 3 and image.shape[2] == 3:
        color_space = determine_best_color_space(image)

        if color_space == "LAB":
            lab = cv2.cvtColor(image, cv2.COLOR_BGR2LAB)
            l, a, b = cv2.split(lab)
            l = apply_clahe_to_channel(l, clip_limit, tile_grid_size)
            merged = cv2.merge((l, a, b))
            contrast_image = cv2.cvtColor(merged, cv2.COLOR_LAB2BGR)
        elif color_space == "YCrCb":
            ycrcb = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb)
            y, cr, cb = cv2.split(ycrcb)
            y = apply_clahe_to_channel(y, clip_limit, tile_grid_size)
            merged = cv2.merge((y, cr, cb))
            contrast_image = cv2.cvtColor(merged, cv2.COLOR_YCrCb2BGR)
        else:
            raise ValueError("Unsupported color space.")
    else:
        contrast_image = apply_clahe_to_channel(image, clip_limit, tile_grid_size)

    return contrast_image


def image_processing(file_bytes: bytes):
    try:
        image_flag = is_image(file_bytes)
        if image_flag:
            # Convert file contents to a numpy array and read the image
            np_arr = np.frombuffer(file_bytes, np.uint8)
            input_image = cv2.imdecode(np_arr, cv2.IMREAD_GRAYSCALE)

            if input_image is None:
                return False, None, None
            # Enhance the brightness
            bright_image = enhance_brightness(input_image, 1.3)

            # Increase the contrast
            contrast_image = increase_contrast(bright_image)

            return contrast_image
        else:
            return file_bytes
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Image processing failed",
        )
