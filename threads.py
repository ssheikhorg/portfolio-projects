import time
from threading import Thread


def complex_calculation():
    start = time.time()
    print('Started calculating...')
    [x ** 2 for x in range(20000000)]
    print(f'complex_calculation, {time.time() - start}')


if __name__ == '__main__':
    # Single Thread
    start = time.time()
    complex_calculation()
    print(f'Single thread total time: {time.time() - start}')

    thread1 = Thread(target=complex_calculation)
    thread2 = Thread(target=complex_calculation)
    thread3 = Thread(target=complex_calculation)

    start = time.time()

    thread1.start()
    thread1.join()
    print(f'First thread total time: {time.time() - start}')
    thread2.start()
    thread2.join()
    print(f'Second thread total time: {time.time() - start}')
    thread3.start()
    thread3.join()
    print(f'Third thread total time: {time.time() - start}')


