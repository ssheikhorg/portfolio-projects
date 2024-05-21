from pathlib import Path

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import col, length, lit
from pyspark.sql.types import StructType, StructField, StringType, IntegerType


class DataValidator:
    def __init__(self, file_path: str, schema: StructType):
        self.spark = SparkSession.builder \
            .appName("Data Validation and Storage") \
            .getOrCreate()
        self.file_path = file_path
        self.schema = schema

    def read_data(self) -> DataFrame:
        # Read data with schema validation
        df = self.spark.read.schema(self.schema).csv(self.file_path)
        return df

    def validate_field_lengths(self, df: DataFrame) -> DataFrame:
        validations = [
            (length(col("Date")) <= 10, "Date length exceeds 10"),
            (length(col("Time")) <= 8, "Time length exceeds 8"),
            # Add other validations here as per your requirement
            (length(col("Postcode")) <= 8, "Postcode length exceeds 8"),
            (length(col("UDPRN")) <= 8, "UDPRN length exceeds 8")
        ]

        for validation, error_message in validations:
            df = df.filter(validation).withColumn("Error", lit(error_message))

        return df

    def filter_postcode(self, df: DataFrame, postcode: str) -> DataFrame:
        return df.filter(col("Postcode") == postcode)

    def write_data(self, df: DataFrame, output_path: str) -> None:
        df.write.parquet(output_path)

    def process_data(self, postcode: str, output_path: str) -> None:
        df = self.read_data()
        df = self.validate_field_lengths(df)
        df = self.filter_postcode(df, postcode)
        self.write_data(df, output_path)
        self.spark.stop()


if __name__ == "__main__":
    schema = StructType([
        StructField("Date", StringType(), True),
        StructField("Time", StringType(), True),
        StructField("AmendmentType", IntegerType(), True),
        StructField("ReasonForAmendment", IntegerType(), True),
        StructField("Postcode", StringType(), True),
        StructField("PostTown", StringType(), True),
        StructField("DependentLocality", StringType(), True),
        StructField("DoubleDependentLocality", StringType(), True),
        StructField("ThoroughfareDescriptor", StringType(), True),
        StructField("DependentThoroughfareDescriptor", StringType(), True),
        StructField("BuildingNumber", StringType(), True),
        StructField("BuildingName", StringType(), True),
        StructField("SubBuildingName", StringType(), True),
        StructField("POBox", StringType(), True),
        StructField("DepartmentName", StringType(), True),
        StructField("OrganisationName", StringType(), True),
        StructField("UDPRN", StringType(), True),
        StructField("PostcodeType", StringType(), True),
        StructField("SUOrganisationIndicator", StringType(), True),
        StructField("DeliveryPointSuffix", StringType(), True),
        StructField("AddressKey", StringType(), True),
        StructField("OrganisationKey", StringType(), True),
        StructField("NumberOfHouseholds", IntegerType(), True),
        StructField("LocalityKey", StringType(), True)
    ])
    print("Processing data...")
    validator = DataValidator("CSV PAF Changes.csv", schema)
    print("Reading data...")
    # output path cwd + "output"
    path = Path().absolute() / "output"
    print("Output path:", path)
    validator.process_data("PL4 8RU", str(path))
    print("Data processing completed.")
