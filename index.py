"""
For beginWord = "hit", endWord = "cog", and wordList = ["hot", "dot", "dog", "lot", "log", "cog"], the output should be
solution(beginWord, endWord, wordList) = 5
"""
from collections import deque


def solution(beginWord, endWord, wordList):
    graph = {}
    wordList.append(beginWord)
    for word in wordList:
        graph[word] = []
        for other_word in wordList:
            if word != other_word and is_adjacent(word, other_word):
                graph[word].append(other_word)
    return bfs(beginWord, endWord, graph)


def is_adjacent(word1, word2):
    count = 0
    for i in range(len(word1)):
        if word1[i] != word2[i]:
            count += 1
    return count == 1


def bfs(beginWord, endWord, graph):
    queue = deque()
    queue.append(beginWord)
    visited = set()
    visited.add(beginWord)
    edges = 0
    while queue:
        edges += 1
        for _ in range(len(queue)):
            current_word = queue.popleft()
            if current_word == endWord:
                return edges
            for neighbor in graph[current_word]:
                if neighbor not in visited:
                    queue.append(neighbor)
                    visited.add(neighbor)
    return 0


if __name__ == "__main__":
    print(solution("hit", "cog", ["hot", "dot", "dog", "lot", "log", "cog"]))
    # print(solution("a", "c", ["a", "b", "c"]))
# """
# Given an array of integers a, your task is to calculate the digits that occur the most number of times in the array. Return the array of these digits in ascending order.
# For a = [25, 2, 3, 57, 38, 41],
# the output should be solution(a) = [2, 3, 5]
# """
#
# def solution(a):
#     # Write your code here
#     # 1. Get the digits of each number
#     # 2. Count the digits
#     # 3. Get the max count
#     # 4. Get the digits with the max count
#     # 5. Return the digits in ascending order
#     digits = []
#     for num in a:
#         digits += list(str(num))
#     digits = list(map(int, digits))
#
#     digit_count = {}
#     for digit in digits:
#         if digit in digit_count:
#             digit_count[digit] += 1
#         else:
#             digit_count[digit] = 1
#     max_count = max(digit_count.values())
#     max_digits = []
#     for digit in digit_count:
#         if digit_count[digit] == max_count:
#             max_digits.append(digit)
#     return sorted(max_digits)
#
#
#
# if __name__ == "__main__":
#     print(solution([25, 2, 3, 57, 38, 41]))
# print(solution([4, 5, 4, 2, 2, 25]))

# def moveZeroes(nums: list[int]):
#     j = 0
#     for num in nums:
#         if (num != 0):
#             nums[j] = num
#             j += 1
#
#     for x in range(j, len(nums)):
#         nums[x] = 0
#
#     return nums
#
#
# def numRescueBoats(people: list[int], limit: int) -> int:
#     people.sort()
#
#     n = len(people)
#     left = 0
#     right = len(people)-1
#     boats_number = 0
#
#     while(left <= right):
#         if(left == right):
#             boats_number += 1
#             break
#
#         if(people[left]+people[right] <= limit):
#             left += 1
#
#         right -= 1
#         boats_number += 1
#
#     return boats_number
#
#
#
# if __name__ == "__main__":
#     # print(moveZeroes([0,12,2,0,45]))
#     print(numRescueBoats([2,1,3,4], 4))
