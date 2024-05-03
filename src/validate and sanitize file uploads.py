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
    allowed_formats = ["application/pdf", "image/jpeg", "image/png", "image/gif", "image/pjpeg", "application/octet-stream"]
    
    if f"{mime_type}/{sub_type}" not in allowed_formats:
        logs('warning', f"Invalid file format: {mime_type}/{sub_type}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file format: {mime_type}/{sub_type}. File must be in PDF or image format (JPEG, PNG, GIF, JFIF).",
        )
    logs('info', f"File format validated: {mime_type}/{sub_type}")
    return file

async def sanitize_file_content(file: UploadFile = File(...)):
    """
    This function sanitizes the uploaded file based on its format.
    It sanitizes the file, logs an info message, and returns the sanitized file.
    If an error occurs during sanitization, it logs a critical error and raises an HTTPException.
    """
    file_extension = file.filename.split(".")[-1].lower()

    if file_extension == "pdf":
        try:
            with file.file as f:
                f.seek(0)
                reader = PdfReader(f)
                writer = PdfWriter()

                for page in reader.pages:
                    writer.add_page(page)

                output_pdf = BytesIO()
                writer.write(output_pdf)
                output_pdf.seek(0)
                sanitized_file = UploadFile(filename=file.filename, file=output_pdf)

                logs('info', "PDF sanitization successful!")
        except Exception as e:
            logs('critical', f"PDF sanitization failed due to error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid PDF file. Error: {str(e)}",
            )
    else:
        try:
            with file.file as f:
                image = Image.open(f)
                output_image = BytesIO()
                # Treat 'jfif' files as 'jpeg' files when saving the image
                image_format = 'JPEG' if file_extension == 'jfif' else file_extension.upper()
                image.save(output_image, format=image_format)
                output_image.seek(0)
                sanitized_file = UploadFile(filename=file.filename, file=output_image)

                logs('info', "Image sanitization successful!")
        except IOError as e:
            logs('critical', f"Image sanitization failed due to error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid image file. Error: {str(e)}",
            )

    return sanitized_file
