from io import BytesIO

import magic
from fastapi import HTTPException, status
from pikepdf import Pdf, PdfError
from PIL import Image


async def sanitize_pdf(file_bytes: bytes):
    """
    Sanitizes PDF files using pikepdf to remove potential harmful content and metadata.
    """
    try:
        # Read the file into a BytesIO object
        file_like_object = BytesIO(file_bytes)

        with Pdf.open(file_like_object) as pdf:
            # Remove document-level JavaScript and actions
            if "/AA" in pdf.Root:
                del pdf.Root["/AA"]
            if "/OpenAction" in pdf.Root:
                del pdf.Root["/OpenAction"]
            if "/JavaScript" in pdf.Root:
                del pdf.Root["/JavaScript"]

            # Process each page in the document
            for page in pdf.pages:
                if "/AA" in page:
                    del page["/AA"]  # Page level additional actions
                if "/Annots" in page:
                    annotations = page["/Annots"]
                    for annot in list(annotations):
                        if "/JS" in annot or "/Action" in annot:
                            annotations.remove(annot)

            # Process and neutralize forms
            if "/AcroForm" in pdf.Root:
                acroform = pdf.Root["/AcroForm"]
                if "/Fields" in acroform:
                    fields = acroform["/Fields"]
                    for field in list(fields):
                        if "/AA" in field or "/JS" in field:
                            fields.remove(field)
                del pdf.Root["/AcroForm"]
            output_pdf = BytesIO()
            pdf.save(output_pdf)
            output_pdf.seek(0)
            return output_pdf.getvalue()  # Return output_pdf instead of pdf
    except PdfError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"PDF sanitization error: {str(e)}",
        )


async def sanitize_image(file_bytes: bytes):
    """
    Sanitizes image files by resaving them to strip out potential embedded harmful content and metadata.
    """
    try:
        # Read the file into a BytesIO object
        file_like_object = BytesIO(file_bytes)

        with Image.open(file_like_object) as image:
            output_image = BytesIO()
            format_to_use = (
                "JPEG" if image.format in ["JPEG", "JFIF", "PJPEG"] else image.format
            )
            image.save(output_image, format=format_to_use)
            output_image.seek(0)
        return output_image.getvalue()
    except IOError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Image sanitization error: {str(e)}",
        )


async def sanitize_file_content(file: bytes, file_extension: str):
    """
    executes the appropriate sanitization function.
    """
    try:
        # Use clean_file here
        if file_extension == "pdf":
            sanitized_file = await sanitize_pdf(file)  # Use clean_file here
        else:
            sanitized_file = await sanitize_image(file)  # Use clean_file here

        return sanitized_file
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"File sanitization error: {str(e)}",
        )
