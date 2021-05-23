from typing import Counter


class SLLNode:

    def __init__(self, data):
        self.data = data
        self.next = None

    def __repr__(self):
        return f"SLLNode object: {self.data}"

    def get_data(self):
        """Return the self.data attribute."""
        return self.data
    
    def set_data(self, new_data):
        """Replace the existing value of the self.data
        attribute with new_data parameter."""
        self.data = new_data

    def get_next(self):
        """Return the self.next attribute."""
        return self.next

    def set_next(self, new_next):
        """Replace the existing value of the self.next
        attribute with new_next parameter."""
        self.next = new_next


class SLL:
    def __init__(self):
        self.head = None

    def __repr__(self) -> str:
        return f"SLL object: head={self.head}"
    
    def is_empty(self):
        """returns True if the linked list is empty. Otherwise False"""
        return self.head is None
        
    def add_front(self, new_data):
        """Add a Node whose data is the new_data argument to the
        front of the Linked List."""
        temp = SLLNode(new_data) #created singly linked list node
        temp.set_next(self.head) # to change set_next value to current value
        self.head = temp
        
    def size(self):
        """Traverse the Linked List and returns an integer value representing
        the number of nodes in the Linked List.

        The time complexity is 0(n) because every Node in the Linked List must
        be visited in order to calculate the size of the linked list."""
        size = 0
        if self.head is None:
            return 0
        
        current = self.head
        while current is not None: # while there are still nodes left to count
            size += 1
            current = current.get_next()
        return size
        
    def search(self, data):
        """Traerses the Linked List and returns True if the data searched for
        is present in one of the Nodes. Otherwise, it returns False.
        
        The time complexity is 0(n) because in the worst case"""
        if self.head is None:
            return "Linked List is empty. No Nodes to search."
        current = self.head
        while current is not None:
            if current.get_data() == data:
                return True
            else:
                current = current.get_next()
        return False

    def remove(self, data):
        """Removes the first occurence of a Node that contains the data argument
        as its self.data variable. Returns nothing.
        
        The Time Complexity is 0(n) because in the worst case we have to visit
        every Node before we find the one we need to remove."""
        if self.head is None:
            return "Linked List is empty. No Nodes to remove."
        
        current = self.head
        previous = None
        found = False
        while not found:
            if current.get_data() == data:
                found = True
            else:
                if current.get_data() == data:
                    found = True
                else:
                    if current.get_next() == None:
                        return "A Node with that data value is not present."
                    else:
                        previous = current
                        current = current.get_next()
        if previous is None:
            self.head = current.get_next()
        else:
            previous.set_next(current.get_next())

"""
node1 = SLLNode('apple')
node2 = SLLNode('carrot')
node1.set_next(node2)
print(node1.get_data())
print(node1.get_next())
"""
"""
sll = SLL()
sll.head
sll.add_front('berry')
print(sll.head)
"""
"""
sll = SLL()
print(sll.size())
sll.add_front(1)
sll.add_front(2)
sll.add_front(3)
print(sll.size())
"""
"""
sll = SLL()
print(sll.search(3))
sll.add_front(1)
sll.add_front(2)
sll.add_front(3)
print(sll.search('bird'))
"""
"""
sll = SLL()
print(sll.remove(15))
sll.add_front(27)
print(sll.remove(17))
print(sll.remove(27))
"""