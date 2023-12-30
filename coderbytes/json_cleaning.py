# Django JSON cleaning
"""
Imagine you are writing an application to parse JSON data. In the Python file,
write a program to perform a GET request on the route https://coderbyte.com/api/challenges/json/json-cleaning
and the clean the object according to the following rules: Remove all keys that have values of N/A, -, or empty strings.
If one of these values appears in an array, remove that element from the array. Remove the single item from the array.
Then print the modified object as a string.

Input
{"name":{"first":"Daniel","middle":"N/A","last":"Smith"},"age":45}
Output
{"name":{"first":"Daniel","last":"Smith"},"age":45}
"""

import requests
import json

def clean_data():
    r = requests.get('https://coderbyte.com/api/challenges/json/json-cleaning')
    data = r.json()
    print(f'Raw data: {data}')
    cleaned_data = {}
    for k, v in data.items():
        strp_v = ['N/A', '-', '']

        # Check if the value is a dictionary and contains stripped values
        if isinstance(v, dict):
            cleaned_dict = {i_key: i_value for i_key, i_value in v.items() if i_value not in strp_v}
            if cleaned_dict:
                cleaned_data[k] = cleaned_dict
        # If it's a list, filter out the stripped values and remove single items
        elif isinstance(v, list):
            cleaned_list = [item for item in v if item not in strp_v]
            if len(cleaned_list) > 1:
                cleaned_data[k] = cleaned_list
            elif len(cleaned_list) == 1:
                cleaned_data[k] = cleaned_list[0]
        # If it's not a dictionary or a list and not in stripped values, add it to cleaned data
        elif v not in strp_v:
            cleaned_data[k] = v

    print(f'Cleaned data: {cleaned_data}')
    return json.dumps(cleaned_data)


if __name__ == "__main__":
    result = clean_data()
    print(result)

