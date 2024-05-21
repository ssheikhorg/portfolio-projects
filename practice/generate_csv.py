"""OrderID,ProductID,ProductName,Category,Quantity,PricePerUnit,SaleDate,Status,Region
1001,501,"Laptop 15'","Electronics",2,1200,"2023-05-10","Completed","North"
1002,204,"Winter Jacket","Clothing",1,85,"2023-05-12","Cancelled","South"
1003,301,"Smartphone 12","Electronics",3,700,"2023-05-11","Completed","East"
1004,512,"Bluetooth Headphones","Electronics",1,150,"2023-05-15","Pending","West"
1005,403,"Sports Watch","Electronics",2,220,"2023-05-10","Completed","East"""

import csv


def generate_csv(data: list) -> None:
    with open('sales.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(
            ["OrderID", "ProductID", "ProductName", "Category", "Quantity", "PricePerUnit", "SaleDate", "Status",
             "Region"])
        writer.writerows(data)
        print("CSV file created successfully.")


if __name__ == '__main__':
    mock_data = [
        [1001, 501, "Laptop 15'", "Electronics", 2, 1200, "2024-03-10", "Completed", "North"],
        [1002, 204, "Winter Jacket", "Clothing", 1, 85, "2024-03-12", "Cancelled", "South"],
        [1003, 301, "Smartphone 12", "Electronics", 3, 700, "2024-03-11", "Completed", "East"],
        [1004, 512, "Bluetooth Headphones", "Electronics", 1, 150, "2024-03-15", "Pending", "West"],
        [1005, 403, "Sports Watch", "Electronics", 2, 220, "2024-03-10", "Completed", "East"]
    ]
    generate_csv(mock_data)
   