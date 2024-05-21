import pandas as pd

# Load the CSV file into a DataFrame
df = pd.read_csv('sales.csv')

# Display the first few rows of the DataFrame
print("Initial data:")
display(df.head())

# Filter out rows where the status is 'pending' or 'cancelled'
df = df[df['Status'] == 'Completed']

# Convert the 'SaleDate' from string to datetime
df['SaleDate'] = pd.to_datetime(df['SaleDate'])

# Extract the year from 'SaleDate' and create a new column
df['Year'] = df['SaleDate'].dt.year

# Display the cleaned data
print("\nCleaned data:")
display(df.head())

# Perform aggregations
# Total sales per region
total_sales_per_region = df.groupby('Region')['PricePerUnit'].sum().reset_index()
print("\nTotal Sales Per Region:")
display(total_sales_per_region)

# Average sales per product
average_sales_per_product = df.groupby('ProductName')['PricePerUnit'].mean().reset_index()
print("\nAverage Sales Per Product:")
display(average_sales_per_product)

# Save the processed DataFrame to a new CSV file
df.to_csv('processed_sales.csv', index=False)
print("\nProcessed data has been saved to 'processed_sales.csv'.")

# Apache Spark

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, year, sum, avg

# Initialize a Spark session
spark = SparkSession.builder.master("local").appName("Sales Analysis").getOrCreate()

# Load the CSV file into a DataFrame
df = spark.read.csv('sales.csv', header=True, inferSchema=True)

# Display the initial data
print("Initial data:")
df.show()

# Filter out rows where the status is 'pending' or 'cancelled'
df_filtered = df.filter(df['Status'] == 'Completed')

# Convert the 'SaleDate' from string to datetime if needed and extract the year
df_filtered = df_filtered.withColumn('SaleDate', col('SaleDate').cast('date'))  # Casting if not automatically inferred
df_filtered = df_filtered.withColumn('Year', year(col('SaleDate')))

# Display the cleaned data
print("\nCleaned data:")
df_filtered.show()

# Perform aggregations
# Total sales per region
total_sales_per_region = df_filtered.groupBy('Region').agg(sum('PricePerUnit').alias('TotalSales'))
print("\nTotal Sales Per Region:")
total_sales_per_region.show()

# Average sales per product
average_sales_per_product = df_filtered.groupBy('ProductName').agg(avg('PricePerUnit').alias('AveragePrice'))
print("\nAverage Sales Per Product:")
average_sales_per_product.show()

# Save the processed DataFrame to a new CSV file
df_filtered.write.csv('processed_sales.csv', header=True, mode='overwrite')
print("\nProcessed data has been saved to 'processed_sales.csv'.")
