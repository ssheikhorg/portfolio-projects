import os
from pathlib import Path
import tempfile
from io import BytesIO
from typing import Optional

import cv2
import fitz
import numpy as np
from fastapi import HTTPException
from paddleocr import PaddleOCR
from PIL import Image
from reportlab.lib.colors import black, red
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from api.process_file.processor import create_tmp_file

pdfmetrics.registerFont(TTFont("GermanFont", Path("static") / "fonts" / "german.ttf"))


def process_ocr_result(c, result, width, height, draw_debug=True):
    for line in result:
        box = np.array(line[0]).astype(np.int64).reshape([-1, 1, 2])
        text, score = line[1]
        x1, y1 = box[0][0]
        x2, y2 = box[2][0]
        box_width = x2 - x1
        box_height = y2 - y1
        font_size = 0.8 * box_height
        c.setFont("GermanFont", font_size)
        text_width = c.stringWidth(text, "GermanFont", font_size)
        if text_width > box_width:
            font_size *= box_width / text_width
            c.setFont("GermanFont", font_size)

        text_x = x1 + (box_width - c.stringWidth(text, "GermanFont", font_size)) / 2
        text_y = height - y2 + (box_height - font_size) / 2

        if draw_debug:
            c.setStrokeColor(red)
            c.rect(x1, height - y2, box_width, box_height, fill=0, stroke=1)
            c.setFillColor(black)
            c.drawString(text_x, text_y, text)
        else:
            c.setFillColorRGB(1, 1, 1, 0)  # Invisible text
            c.drawString(text_x, text_y, text)


def save_pdf_ocr(result, pdf_path, tmp_dir: str, draw_debug=True) -> str:
    output_pdf = BytesIO()
    c = canvas.Canvas(output_pdf)
    with fitz.open(pdf_path) as pdf:
        for pg, page_result in enumerate(result):
            page = pdf[pg]
            mat = fitz.Matrix(2, 2)
            pm = page.get_pixmap(matrix=mat, alpha=False)
            if pm.width > 2000 or pm.height > 2000:
                pm = page.get_pixmap(matrix=fitz.Matrix(1, 1), alpha=False)
            img = Image.frombytes("RGB", [pm.width, pm.height], pm.samples)
            img_array = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
            height, width = img_array.shape[:2]
            c.setPageSize((width, height))
            pil_img = Image.fromarray(cv2.cvtColor(img_array, cv2.COLOR_BGR2RGB))
            c.drawInlineImage(pil_img, 0, 0, width=width, height=height)
            if page_result is not None:
                process_ocr_result(c, page_result, width, height, draw_debug)
            c.showPage()
    c.save()
    output_pdf.seek(0)
    final_pdf_path = os.path.join(tmp_dir, "result.pdf")
    with open(final_pdf_path, "wb") as f:
        f.write(output_pdf.getvalue())
    return final_pdf_path


def pdf_to_image(pdf_bytes):
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        page = doc.load_page(0)
        pix = page.get_pixmap()
        img_data = pix.tobytes("png")
    return Image.open(BytesIO(img_data))


def process_image_with_ocr(image, result, draw_debug=True):
    width, height = image.size

    # Create a PDF canvas
    pdf_buffer = BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=(width, height))

    # Draw the original image
    c.drawImage(ImageReader(image), 0, 0, width=width, height=height)

    for line in result[0]:
        box = np.array(line[0]).astype(np.int64).reshape([-1, 1, 2])
        text, score = line[1]

        # Ensure box coordinates are in the correct order
        x1, y1 = np.min(box, axis=0)[0]
        x2, y2 = np.max(box, axis=0)[0]

        # Calculate box dimensions
        box_width = x2 - x1
        box_height = y2 - y1

        # Determine font size
        font_size = int(min(box_height * 0.8, box_width / (len(text) * 0.6)))
        font_size = max(10, font_size)  # Ensure minimum font size of 10

        # Set font
        c.setFont("GermanFont", font_size)

        if draw_debug:
            # Draw bounding box
            c.setStrokeColorRGB(1, 0, 0)  # Red color
            c.rect(x1, height - y2, box_width, box_height, fill=0, stroke=1)
            # Draw visible text
            c.setFillColorRGB(0, 0, 0)  # Black color
            c.drawString(x1, height - y1 - font_size, text)
        else:
            # Draw invisible text
            c.setFillColorRGB(1, 1, 1, 0)  # White color with 0 alpha (invisible)
            c.drawString(x1, height - y1 - font_size, text)

    c.save()

    # Convert PDF to image
    pdf_bytes = pdf_buffer.getvalue()
    result_image = pdf_to_image(pdf_bytes)

    return result_image


def save_unprocessed_image_ocr(result, tmp_file_path, draw_debug=True):
    # Open the image
    with Image.open(tmp_file_path) as image:
        original_format = image.format
        result_image = process_image_with_ocr(image, result, draw_debug)

    # Save the result image in the original format
    result_image.save(tmp_file_path, format=original_format)
    return tmp_file_path


def save_image_ocr(result, contrast_image: np.ndarray, draw_debug=True):
    # Convert numpy array to PIL Image
    image = Image.fromarray(cv2.cvtColor(contrast_image, cv2.COLOR_BGR2RGB))
    result_image = process_image_with_ocr(image, result, draw_debug)

    # Save the result image to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_file:
        result_image.save(tmp_file, format="PNG")
        tmp_file_path = tmp_file.name

    return tmp_file_path


async def process_OCR(
        file_name: str,
        file_extension: str,
        file_bytes: Optional[bytes] = None,
        contrast_image: Optional[np.ndarray] = None,
):
    # Validate file extension
    mime_map = {
        "pdf": "application/pdf",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "jfif": "image/jpeg",
        "pjpeg": "image/jpeg",
        "png": "image/png",
    }

    if file_extension.lower() not in mime_map:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file extension: {file_extension}",
        )

    # Instantiate an OCR agent
    ocr_agent = PaddleOCR(
        use_angle=True,
        lang="german",
    )

    if file_bytes:
        tmp_file_path = create_tmp_file(file_bytes, file_name)
        if file_extension.lower() == "pdf":
            # Process PDF
            result = ocr_agent.ocr(tmp_file_path, cls=True)
            tmp_dir = tempfile.mkdtemp()
            ocr_file_path = save_pdf_ocr(result, tmp_file_path, tmp_dir)
            return ocr_file_path
        else:
            result = ocr_agent.ocr(tmp_file_path, cls=True)
            ocr_file_path = save_unprocessed_image_ocr(
                result, tmp_file_path
            )
            return ocr_file_path
    else:
        if contrast_image is not None:
            # Process image
            result = ocr_agent.ocr(contrast_image, cls=True)
            ocr_file_path = save_image_ocr(result, contrast_image)
            return ocr_file_path
        else:
            raise HTTPException(
                status_code=400,
                detail="No file data provided for OCR processing",
            )
