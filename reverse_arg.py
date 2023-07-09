"""
def reversed_args(f):
    return f

int_func_map = {
    'pow': pow,
    'cmp': lambda a, b: 0 if a == b else [1, -1][a < b],
}

string_func_map = {
    'join_with': lambda separator, *args: separator.join(args),
    'capitalize_first_and_join': lambda first, *args: ''.join([first.upper()] + list(args)),
}

queries = int(input())
for _ in range(queries):
    line = input().split()
    func_name, args = line[0], line[1:]
    if func_name in int_func_map:
        args = list(map(int, args))
        print(reversed_args(int_func_map[func_name])(*args))
    else:
        print(reversed_args(string_func_map[func_name])(*args))


for exmaple, if the original function is a pow function, f(2,3) = 8, 2^3 = 8
then the correct result is a function g, with g(3,2) = 9, because 3^2 = 9
"""

def reversed_args(f):
    def g(*args):
        return f(*args[::-1])
    return g

int_func_map = {
    'pow': pow,
    'cmp': lambda a, b: 0 if a == b else [1, -1][a < b],
}

string_func_map = {
    'join_with': lambda separator, *args: separator.join(args),
    'capitalize_first_and_join': lambda first, *args: ''.join([first.upper()] + list(args)),
}

queries = int(input())
for _ in range(queries):
    line = input().split()
    func_name, args = line[0], line[1:]
    if func_name in int_func_map:
        args = list(map(int, args))
        print(reversed_args(int_func_map[func_name])(*args))
    else:
        print(reversed_args(string_func_map[func_name])(*args))
