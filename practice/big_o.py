def pair_sum_sequence(n):
    sum = 0
    for i in range(n):
        sum += pair_sum(i, i + 1)
    return sum


def pair_sum(a, b):
    return a + b


if __name__ == "__main__":
    print(pair_sum_sequence(3))
