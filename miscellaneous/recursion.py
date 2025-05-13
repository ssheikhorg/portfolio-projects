# factorial
def fact(n):
    if n == 0:
        return 1
    else:
        return n * fact(n - 1)


print(fact(4))

"""
#fibonacci recurssion
def fib(n):
    #check the input is a positive number
    if type(n) != int:
        raise TypeError("n must be a positive number")
    if n < 1:
        raise ValueError("n must be a positive int")

    if n == 1:
        return 1
    elif n == 2:
        return 1
    elif n > 2:
        return fib(n-1) + fib(n-2)
        
for n in range(1, 20):
    print(n, ":", fib(n))
"""
