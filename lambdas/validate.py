import io
import re
import json
from dataclasses import dataclass, field
from typing import Optional
import boto3
import pandas as pd

s3_client = boto3.client('s3')


@dataclass
class ScreeningData:
    Source_Name: str
    Source_OID: str
    ORG_Unique_ID: str
    First_Name: str
    Last_Name: str
    DOB: str
    Sex: str
    Race: str
    Ethnicity: str
    Screen_Date: str
    Screening_Practice_OID: str
    Screening_Practice_Name: str
    Referral_Date: str
    Care_Coordination_Performed: str
    Patient_Assisted_In_MI_Bridges: str
    Question_Id: str
    Question_Text: str
    Question_Code: str
    Question_Code_System: str
    Domain: str
    Answer: str
    Answer_Code: str
    Need_Identified: str
    Screen_Id: str
    Z_Code: str
    Screening_Provider_NPI: str
    Screening_Provider_Name: str
    Screening_Tool_Code: str
    Intervention_Category: Optional[str] = None
    Row_ID: Optional[str] = None
    SSN: Optional[str] = None
    City: Optional[str] = None
    State: Optional[str] = None
    Address_1: Optional[str] = None
    Address_2: Optional[str] = None
    Postal_Code: Optional[str] = None
    Screenee_Unique_ID: Optional[str] = None
    SSN4: Optional[str] = None
    Common_Key: Optional[str] = None
    Mobile_Number: Optional[str] = None
    Home_Number: Optional[str] = None
    Screening_Organization_OID: Optional[str] = None
    Screening_Organization_Name: Optional[str] = None
    Screening_Question_Code: Optional[str] = None
    Screening_Answer_Code: Optional[str] = None
    Intervention_Date: Optional[str] = None
    Screening_Provider_First_Name: Optional[str] = None
    Screening_Provider_Last_Name: Optional[str] = None

    def validate(self) -> bool:
        validations = [
            self.validate_phone_number(),
            self.validate_situational_fields(),
            self.validate_address_related_fields()
        ]
        return all(validations)

    def validate_phone_number(self) -> bool:
        if self.Mobile_Number and not re.match(r'^\d{10}$', self.Mobile_Number):
            return False
        elif self.Home_Number and not re.match(r'^\d{10}$', self.Home_Number):
            return False
        return True

    def validate_situational_fields(self) -> bool:
        return any([
            self.Mobile_Number,
            self.Home_Number,
            self.SSN,
            self.Address_1
        ])

    def validate_address_related_fields(self) -> bool:
        if not self.Address_1:
            return True
        if not (self.City and self.State and self.Postal_Code):
            return False
        return True


def handler(event, context) -> dict:
    print("Validate Event: ", event)
    is_valid = True
    try:
        # Extract bucket and key from the event
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        object_key = event['Records'][0]['s3']['object']['key']

        # Download the file from S3
        file_obj = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        file_content = file_obj['Body'].read().decode('utf-8', errors='ignore')

        # Read the CSV content
        csv_reader = pd.read_csv(io.StringIO(file_content))
        print("CSV content: ", csv_reader)
        # csv_reader = pd.read_csv(io.StringIO(open("docs/examples.csv").read()))

        for index, row in csv_reader.iterrows():
            screening_data = ScreeningData(**row)
            if not screening_data.validate():
                is_valid = False
                break
        print("Validation result: ", is_valid)
        return {
              "statusCode": 200 if is_valid else 400,
              "body": {
                "message": "File validation successful" if is_valid else "File validation failed",
                "valid": is_valid
              }
            }
    except Exception as e:
        print(e)
        return {
            "statusCode": 500,
            "body": {
                "message": f"An error occurred: {str(e)}",
                "valid": False
            }
        }
