
def sum_of_squares(nums: list) -> int | None:
    # time complexity: overall time complexity of the algorithm is O(n)
    # space complexity: O(n)
    if len(nums) == 1:
        return None
    return sum(map(lambda x: x ** 2, filter(lambda x: x > 0, nums)))


if __name__ == "__main__":
    print(sum_of_squares([2]))
    print(sum_of_squares([4]))
    print(sum_of_squares([3, -1, 1, 14]))
    print(sum_of_squares([5]))
    print(sum_of_squares([9, 6, -53, 32, 16]))
