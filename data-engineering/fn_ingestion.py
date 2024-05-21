from pyspark.sql import SparkSession
from pyspark.sql.functions import col, length, lit
from pyspark.sql.types import StructType, StructField, StringType, IntegerType

# Initialize Spark session
spark = SparkSession.builder \
    .appName("Data Validation and Storage") \
    .getOrCreate()

# Define the schema based on the provided field sizes
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

# Read data with schema validation from "CSV PAF Changes.csv"
df = spark.read.schema(schema).csv("CSV PAF Changes.csv")


# Define validation functions
def validate_field_lengths(df):
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


def filter_postcode(df, postcode):
    return df.filter(col("Postcode") == postcode)


# Validate data
validated_df = validate_field_lengths(df)

# Filter data for specific postcode
filtered_df = filter_postcode(validated_df, "PL4 8RU")

# Store data in Parquet format
filtered_df.write.parquet("path_to_store_parquet_file")

# Stop the Spark session
spark.stop()
