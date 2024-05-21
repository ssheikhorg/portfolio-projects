"""
Have the function LargestFour(arr) take the array of integers stored in arr, and find the four largest elements and return their sum. For example: if arr is [4, 5, -2, 3, 1, 2, 6, 6] then the four largest elements in this array are 6, 6, 4, and 5 and the total sum of these numbers is 21, so your program should return 21. If there are less than four numbers in the array your program should return the sum of all the numbers in the array.
examples:
input: [1, 1, 1, -5] output: -2
input: [0, 0, 2, 3, 7, 1] output: 13
"""


def LargestFour(arr):
    sorted_arr = sorted(arr, reverse=True)

    # Take the sum of the four largest elements if available, otherwise take the sum of all elements
    # result_sum = sum(sorted_arr[:4]) if len(sorted_arr) >= 4 else sum(sorted_arr)
    if len(sorted_arr) >= 4:
        result_sum = sum(sorted_arr[:4])
    else:
        result_sum = sum(sorted_arr)
    return result_sum



if __name__ == "__main__":
    # keep this function call here
    arr_1 = [1, 1, 1, -5]
    arr_2 = [0, 0, 2, 3, 7, 1]
    result_1 = LargestFour(arr_1)
    result_2 = LargestFour(arr_2)
    print(result_1)
    print(result_2)
    # Example usage
    arr = [4, 5, -2, 3, 1, 2, 6, 6]
    result = LargestFour(arr)
    print(result)
