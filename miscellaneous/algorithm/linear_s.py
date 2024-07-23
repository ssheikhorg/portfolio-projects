
def linear_search(haystack: list[int], needle: int) -> bool:
    for i in range(len(haystack)):
        if haystack[i] == needle:
            return True
    return False


if __name__ == "__main__":
    haystack = [12,2,15,16]
    print(linear_search(haystack, 112))
