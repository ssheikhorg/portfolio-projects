"""
implement the class FancyTuple
- The constructor takes 0 to 5 parameters
- The elements of FancyTuple can be accessed as named properties: first, second, third, fourth, fifth.
the expression FancyTuple("dog", "cat").first returns "dog" and FancyTuple("dog", "cat").second returns "cat"
- An AttributeError exceptopm is raised if a non-existing property is accessed FancyTuple("dog", "cat").third raises AttributeError
- len(FancyTuple("dog", "cat")) returns 2
"""


class FancyTuple:
    def __init__(self, *args):
        self.__dict__.update(zip(['first', 'second', 'third', 'fourth', 'fifth'], args))
        self.args = args

    def __len__(self):
        return len(self.args)

    def __repr__(self):
        return 'FancyTuple({})'.format(', '.join(map(repr, self.args)))


if __name__ == "__main__":
    fptr = open(os.environ['OUTPUT_PATH'], 'w')

    n = int(input())
    items = [input() for _ in range(n)]

    t = FancyTuple(*items)

    q = int(input())
    for _ in range(q):
        command = input()
        if command == "len":
            fptr.write(str(len(t)) + "\n")
        else:
            try:
                elem = getattr(t, command)
            except AttributeError:
                fptr.write("AttributeError\n")
            else:
                fptr.write(elem + "\n")
    fptr.close()
