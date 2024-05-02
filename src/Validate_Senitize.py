from fastapi import HTTPException, status, File, UploadFile
from PIL import Image
from io import BytesIO
from PyPDF2 import PdfReader, PdfWriter
from src.utils.Logging import logs

def validate_file_content(file: UploadFile = File(...)):
    """
    This function validates the MIME type of the uploaded file.
    If the MIME type is not in the allowed formats, it logs a warning and raises an HTTPException.
    If the MIME type is valid, it logs an info message and returns the file.
    """
    content_type = file.content_type
    mime_type, sub_type, *_ = content_type.split("/")
    allowed_formats = ["application/pdf", "image/jpeg", "image/png", "image/gif"]
    
    if f"{mime_type}/{sub_type}" not in allowed_formats:
        logs('warning', f"Invalid file format: {mime_type}/{sub_type}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be in PDF or image format (JPEG, PNG, GIF).",
        )
    logs('info', f"File format validated: {mime_type}/{sub_type}")
    return file

async def sanitize_file_content(file: UploadFile = File(...)):
    """
    This function sanitizes the uploaded file based on its format.
    If the file format is not in the allowed formats, it logs a warning and raises an HTTPException.
    If the file format is valid, it sanitizes the file, logs an info message, and returns the sanitized file.
    If an error occurs during sanitization, it logs a critical error and raises an HTTPException.
    """
    file_extension = file.filename.split(".")[-1].lower()
    allowed_formats = ["pdf", "jpg", "jpeg", "png", "gif"]
    
    if file_extension not in allowed_formats:
        logs('warning', f"Invalid file extension: {file_extension}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be in PDF or image format (JPEG, PNG, GIF).",
        )

    if file_extension == "pdf":
        try:
            file.file.seek(0)
            reader = PdfReader(file.file)
            writer = PdfWriter()

            for page in reader.pages:
                writer.add_page(page)

            output_pdf = BytesIO()
            writer.write(output_pdf)
            output_pdf.seek(0)
            sanitized_file = UploadFile(filename=file.filename, file=output_pdf)

            logs('info', "PDF sanitization successful!")
        except Exception as e:
            logs('critical', "PDF sanitization failed", str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid PDF file.",
            )
    else:
        try:
            image = Image.open(file.file)
            output_image = BytesIO()
            image.save(output_image, format=file_extension.upper())
            output_image.seek(0)
            sanitized_file = UploadFile(filename=file.filename, file=output_image)

            logs('info', "Image sanitization successful!")
        except IOError:
            logs('critical', "Image sanitization failed")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid image file.",
            )

    return sanitized_file
