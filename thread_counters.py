import threading
import ctypes

# Global counters
counters = []
for i in range(8):
    counter = ctypes.c_long(0)
    counters.append(counter)

# Thread function to increment a specific counter
def increment_counter(i):
    global counters
    print(f'Counter {i} is located at memory address {hex(id(counters[i]))}')
    for _ in range(10000000):
        counters[i].value += 1

# Create and start 8 threads
threads = []
for i in range(8):
    t = threading.Thread(target=increment_counter, args=(i,))
    threads.append(t)
    t.start()

# Wait for all threads to finish
for t in threads:
    t.join()

# Print final counter values
for i in range(8):
    print(f'Counter {i} value: {counters[i].value}')
