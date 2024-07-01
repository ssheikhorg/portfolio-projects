from io import BytesIO

import cv2
import numpy as np
from fastapi import UploadFile
from pdf2image import convert_from_bytes
from PIL import Image
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas


def export_pdf(
    file_contents, filename, coordinates, image_width, image_height, y_offset=10
):
    # Function to check if file is PDF
    def is_pdf(file_contents):
        return file_contents[:4] == b"%PDF"

    # Create a PDF canvas
    output_pdf = BytesIO()
    c = canvas.Canvas(output_pdf, pagesize=letter)

    if is_pdf(file_contents):
        # Convert single-page PDF to image
        try:
            pdf_images = convert_from_bytes(file_contents)
            if not pdf_images:
                return "Failed to convert PDF to image"
            input_image = pdf_images[0]
        except Exception as e:
            return f"Failed to convert PDF to image: {e}"
    else:
        # Convert file contents to a numpy array and read the image
        np_arr = np.frombuffer(file_contents, np.uint8)
        input_image = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if input_image is None:
            return "Failed to decode image"

        # Convert the OpenCV image (BGR) to RGB format
        input_image = cv2.cvtColor(input_image, cv2.COLOR_BGR2RGB)
        input_image = Image.fromarray(input_image)

    # Draw the original image on the first page
    aspect = image_height / float(image_width)
    img_width_pdf = letter[0]
    img_height_pdf = letter[0] * aspect
    c.drawImage(
        ImageReader(input_image), 0, 0, width=img_width_pdf, height=img_height_pdf
    )

    # Overlay the OCR text invisibly
    c.setFont("Helvetica", 12)
    c.setFillColorRGB(1, 1, 1, alpha=0)

    # Calculate scaling factors
    x_scaling = img_width_pdf / image_width
    y_scaling = img_height_pdf / image_height

    for data in coordinates:
        text = data["text"]
        coords = data["coordinates"]

        # Ensure coordinates are within image dimensions
        x_coord, y_coord = coords[0]

        if (
            x_coord < 0
            or x_coord >= image_width
            or y_coord < 0
            or y_coord >= image_height
        ):
            continue

        # Map coordinates to PDF coordinate system
        x = x_coord * x_scaling
        y = img_height_pdf - y_coord * y_scaling - y_offset
        c.drawString(x, y, text)

    # Save the PDF
    c.save()
    output_pdf.seek(0)
    return UploadFile(filename=filename, file=output_pdf)
