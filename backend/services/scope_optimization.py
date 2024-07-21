import io
import os
import tempfile

import cv2
import fitz
import numpy as np
from PIL import Image
from utils.miscellaneous import create_tmp_file


def scope_opt(input_data, file_extension, file_name, quality=50, max_size=(800, 800)):
    """
    Process an image or PDF, reducing quality and size of images.

    :param input_data: numpy array or file bytes
    :param file_extension: original file extension
    :param quality: JPEG quality (0-95)
    :param max_size: maximum dimensions for the image
    :return: temporary path of the processed file
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        if isinstance(input_data, np.ndarray):
            # Input is a numpy array (image)
            return process_image(
                Image.fromarray(input_data), tmp_dir, quality, max_size
            )
        else:
            # Input is file bytes
            if file_extension == ".pdf":
                # Process PDF
                tmp_pdf_path = create_tmp_file(input_data, file_name)
                return process_pdf(tmp_pdf_path, tmp_dir, quality, max_size)
            else:
                # Process image
                image = Image.open(io.BytesIO(input_data))
                return process_image(image, tmp_dir, quality, max_size)


def process_image(image, tmp_dir, quality, max_size):
    """Process a single image"""
    image.thumbnail(max_size)
    output_path = os.path.join(tmp_dir, "processed_image.jpg")
    image.save(output_path, "JPEG", quality=quality)
    return output_path


def process_pdf(pdf_path, tmp_dir, quality, max_size):
    """Process each page of a PDF"""
    imgs = []
    with fitz.open(pdf_path) as pdf:
        for pg in range(len(pdf)):
            page = pdf[pg]
            mat = fitz.Matrix(2, 2)
            pm = page.get_pixmap(matrix=mat, alpha=False)
            if pm.width > 2000 or pm.height > 2000:
                pm = page.get_pixmap(matrix=fitz.Matrix(1, 1), alpha=False)
            img = Image.frombytes("RGB", [pm.width, pm.height], pm.samples)

            # Apply thumbnail and reduce quality
            img.thumbnail(max_size)
            output_path = os.path.join(tmp_dir, f"processed_image_{pg}.jpg")
            img.save(output_path, "JPEG", quality=quality)

            imgs.append(output_path)

    # Convert modified images back into a single PDF
    final_pdf_path = os.path.join(tmp_dir, "result.pdf")
    images = [Image.open(img_path).convert("RGB") for img_path in imgs]
    images[0].save(final_pdf_path, save_all=True, append_images=images[1:])

    return final_pdf_path
