import cv2
import numpy as np
from paddleocr import PaddleOCR
from pdf2image import convert_from_bytes
from utils.export_to_pdf import export_pdf
from utils.pre_processing import enhance_brightness, increase_contrast


async def process_OCR(file_contents):
    # Function to check if file is PDF
    def is_pdf(file_contents):
        return file_contents[:4] == b"%PDF"

    if is_pdf(file_contents):
        # Convert single-page PDF to image
        try:
            pdf_images = convert_from_bytes(file_contents)
            if not pdf_images:
                return "Failed to convert PDF to image"

            # Convert the first page of PDF to grayscale image
            input_image = cv2.cvtColor(np.array(pdf_images[0]), cv2.COLOR_RGB2GRAY)

            # Get image dimensions for later use in export_pdf
            image_width, image_height = pdf_images[0].size

        except Exception as e:
            return f"Failed to convert PDF to image: {e}"
    else:
        # Convert file contents to a numpy array and read the image
        np_arr = np.frombuffer(file_contents, np.uint8)
        input_image = cv2.imdecode(np_arr, cv2.IMREAD_GRAYSCALE)

        if input_image is None:
            return "Failed to decode image"

        # Get image dimensions for later use in export_pdf
        image_width = input_image.shape[1]
        image_height = input_image.shape[0]

    # Enhance the brightness
    bright_image = enhance_brightness(input_image, 1.3)

    # Increase the contrast
    contrast_image = increase_contrast(bright_image)

    # Instantiate an OCR agent
    ocr_agent = PaddleOCR(lang="german", det_algorithm="DB")

    # Use the OCR agent to extract text from the image
    result = ocr_agent.ocr(contrast_image, cls=False)

    # Initialize list to store text with coordinates
    coordinates = []

    # Check if result is not None
    if result is not None:
        try:
            for line in result:
                for word_info in line:
                    text = word_info[1][0]
                    coords = word_info[0]
                    coordinates.append({"text": text, "coordinates": coords})

        except TypeError:
            print("Error occurred while extracting text and coordinates")
            return "Error occurred while extracting text and coordinates"
    else:
        print("No text found in the image")
        return "No text found in the image"

    # Export the PDF with the original file contents and OCR text with coordinates
    try:
        output_pdf = export_pdf(file_contents, coordinates, image_width, image_height)
        if output_pdf is None:
            print("Failed to create output PDF")
            return "Failed to create output PDF"
        print("PDF created successfully")

    except Exception as e:
        print(f"An error occurred while creating the PDF: {e}")
        return f"An error occurred while creating the PDF: {e}"

    return output_pdf
