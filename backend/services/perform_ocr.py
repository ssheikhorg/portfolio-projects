import os
import tempfile
from typing import Optional

import cv2
import fitz
import numpy as np
from fastapi import HTTPException, status
from paddleocr import PaddleOCR, draw_ocr
from PIL import Image
from utils.log_function import logs
from utils.miscellaneous import create_tmp_file


def save_pdf_ocr(result, pdf_path, tmp_dir: str) -> str:
    logs(
        "info",
        f"Starting OCR save process for PDF: {pdf_path} in temporary directory: {tmp_dir}",
    )
    # Extract images from PDF, map OCR results, and save them as new images
    imgs = []
    with fitz.open(pdf_path) as pdf:
        for pg in range(len(pdf)):
            page = pdf[pg]
            mat = fitz.Matrix(2, 2)
            pm = page.get_pixmap(matrix=mat, alpha=False)
            if pm.width > 2000 or pm.height > 2000:
                pm = page.get_pixmap(matrix=fitz.Matrix(1, 1), alpha=False)
            img = Image.frombytes("RGB", [pm.width, pm.height], pm.samples)
            img = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
            imgs.append(img)
    logs("info", f"Extracted {len(imgs)} images from PDF.")

    # Map OCR results to images and save each image
    for idx in range(len(result)):
        res = result[idx]
        if res is None:
            continue
        image = imgs[idx]
        boxes = [line[0] for line in res]
        txts = [line[1][0] for line in res]
        scores = [line[1][1] for line in res]
        im_show = draw_ocr(
            image, boxes, txts, scores, font_path="/app/static/fonts/german.ttf"
        )
        im_show = Image.fromarray(im_show)
        image_path = os.path.join(tmp_dir, f"result_page_{idx}.jpg")
        im_show.save(image_path)
        logs("info", f"Saved OCR image {image_path}")

    # Convert modified images back into a single PDF
    image_paths = [
        os.path.join(tmp_dir, f"result_page_{i}.jpg") for i in range(len(result))
    ]
    logs("info", f"Image paths for final PDF: {image_paths}")
    images = [Image.open(img_path).convert("RGB") for img_path in image_paths]
    final_pdf_path = os.path.join(tmp_dir, "result.pdf")
    images[0].save(final_pdf_path, save_all=True, append_images=images[1:])
    logs("info", f"Final OCR PDF saved at: {final_pdf_path}")
    return final_pdf_path


def save_image_ocr(result, npimage):
    logs("info", "Starting OCR save process for image.")
    result = result[0]
    image = Image.fromarray(cv2.cvtColor(npimage, cv2.COLOR_BGR2RGB))
    boxes = [line[0] for line in result]
    txts = [line[1][0] for line in result]
    scores = [line[1][1] for line in result]
    im_show = draw_ocr(
        image, boxes, txts, scores, font_path="/app/static/fonts/german.ttf"
    )
    im_show = Image.fromarray(im_show)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp_file:
        im_show.save(tmp_file, format="JPEG")
        temp_file_path = tmp_file.name
    logs("info", f"Saved OCR image at: {temp_file_path}")
    return temp_file_path


def save_unprocessed_image_ocr(result, img_path):
    logs("info", f"Starting OCR save process for unprocessed image: {img_path}")
    result = result[0]
    image = Image.open(img_path).convert("RGB")
    boxes = [line[0] for line in result]
    txts = [line[1][0] for line in result]
    scores = [line[1][1] for line in result]
    im_show = draw_ocr(
        image, boxes, txts, scores, font_path="/app/static/fonts/german.ttf"
    )
    im_show = Image.fromarray(im_show)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp_file:
        im_show.save(tmp_file, format="JPEG")
        temp_file_path = tmp_file.name
    logs("info", f"Saved OCR image at: {temp_file_path}")
    return temp_file_path


async def process_OCR(
    file_name: str,
    file_extension: str,
    file_bytes: Optional[bytes] = None,
    contrast_image: Optional[np.ndarray] = None,
):
    logs(
        "info", f"Processing OCR for file: {file_name} with extension: {file_extension}"
    )
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
        logs("error", f"Unsupported file extension: {file_extension}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension: {file_extension}",
        )

    # Instantiate an OCR agent
    ocr_agent = PaddleOCR(
        use_angle=True,
        lang="german",
    )

    if file_bytes:
        if file_extension.lower() == "pdf":
            # Process PDF
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_pdf_path = create_tmp_file(file_bytes, file_name)
                result = ocr_agent.ocr(tmp_pdf_path, cls=True)
                logs("info", f"OCR result for PDF: {result}")
                ocr_file_path = save_pdf_ocr(result, tmp_pdf_path, tmp_dir)
                return ocr_file_path
        else:
            tmp_img_path = create_tmp_file(file_bytes, file_name)
            result = ocr_agent.ocr(tmp_img_path, cls=True)
            logs("info", f"OCR result for image: {result}")
            ocr_file_path = save_unprocessed_image_ocr(result, tmp_img_path)
            return ocr_file_path
    else:
        if contrast_image is not None:
            # Process image
            result = ocr_agent.ocr(contrast_image, cls=True)
            logs("info", f"OCR result for contrast image: {result}")
            ocr_file_path = save_image_ocr(result, contrast_image)
            return ocr_file_path
        else:
            logs("error", "No contrast image provided for image processing")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No contrast image provided for image processing",
            )
