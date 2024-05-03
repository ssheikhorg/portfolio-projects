from fastapi import HTTPException, status, File, UploadFile
from PIL import Image
from io import BytesIO
from pikepdf import Pdf, PdfError
import magic 
from src.utils.Logging import logs

def get_mime_type(file: BytesIO):
    """
    Determines MIME type of file based on its content using magic
    """
    file.seek(0) 
    mime_type = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0) 
    return mime_type

def validate_mime_type(file: UploadFile, expected_mime_type: str):
    """
    Validates MIME type of file against expected formats using content sniffing.
    Raises HTTPException for unsupported or mismatched formats.
    """
    actual_mime_type = get_mime_type(file.file)
    if actual_mime_type != expected_mime_type:
        logs('warning', f"MIME type mismatch: expected {expected_mime_type}, got {actual_mime_type}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"MIME type mismatch: expected {expected_mime_type}, got {actual_mime_type}."
        )
    logs('info', f"MIME type validated based on content: {actual_mime_type}")

async def sanitize_pdf(file: UploadFile):
    """
    Sanitizes PDF files using pikepdf to remove potential harmful content and metadata.
    """
    try:
        with Pdf.open(file.file) as pdf:
            pdf.remove_unsafe_content()
            output_pdf = BytesIO()
            pdf.save(output_pdf)
            output_pdf.seek(0)
            logs('info', "PDF sanitization successful: harmful content removed.")
        return UploadFile(filename=file.filename, file=output_pdf)
    except PdfError as e:
        logs('critical', f"PDF sanitization failed: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"PDF sanitization error: {str(e)}")

async def sanitize_image(file: UploadFile):
    """
    Sanitizes image files by resaving them to strip out potential embedded harmful content and metadata.
    """
    try:
        with Image.open(file.file) as image:
            output_image = BytesIO()
            format_to_use = 'JPEG' if image.format in ['JPEG', 'JFIF', 'PJPEG'] else image.format
            image.save(output_image, format=format_to_use)
            output_image.seek(0)
            logs('info', "Image sanitization successful: metadata and potential threats removed.")
        return UploadFile(filename=file.filename, file=output_image)
    except IOError as e:
        logs('critical', f"Image sanitization failed: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Image sanitization error: {str(e)}")

async def sanitize_file_content(file: UploadFile = File(...)):
    """
    Determines file type and executes the appropriate sanitization function based on MIME type.
    """
    file_extension = file.filename.split(".")[-1].lower()
    mime_map = {
        "pdf": "application/pdf",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "jfif": "image/jpeg",
        "pjpeg": "image/jpeg",
        "png": "image/png"
    }
    expected_mime_type = mime_map.get(file_extension, "application/octet-stream")
    validate_mime_type(file, expected_mime_type)

    if file_extension == "pdf":
        sanitized_file = await sanitize_pdf(file)
    else:
        sanitized_file = await sanitize_image(file)
    
    logs('info', f"File sanitization successful for: {file.filename}")
    return sanitized_file