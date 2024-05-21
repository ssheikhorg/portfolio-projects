from pyspark.sql.types import StructType, StructField, StringType, IntegerType

schemas = StructType([
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
