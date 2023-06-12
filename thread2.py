import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed

# Create an array of 8 integers
counters = [ctypes.c_int() for _ in range(8)]

def increment_counter(counter_num):
    print(f"Counter {counter_num} is located at memory address {hex(ctypes.addressof(counters[counter_num]))}")
    for i in range(10000000):
        counters[counter_num].value += 1
    return counter_num

if __name__ == '__main__':
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(increment_counter, i) for i in range(8)]
    for future in as_completed(futures):
        counter_num = future.result()
        print(f"Counter {counter_num} final value: {counters[counter_num].value}")

