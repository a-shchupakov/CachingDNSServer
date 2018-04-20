import threading
import time


def parametrized(dec):
    def layer(*args, **kwargs):
        def repl(f):
            return dec(f, *args, **kwargs)
        return repl
    return layer


@parametrized
def locking(func, lock):
    def wrapped(*args, **kwargs):
        with lock:
            return func(*args, **kwargs)
    return wrapped


class CacheDispatcher:
    def __init__(self, func, sleep_time):
        self.thread = threading.Thread(target=self.start_validation, args=(func, sleep_time))
        self.stop = False

    def start_validation(self, func, sleep_time):
        while not self.stop:
            func()
            time.sleep(sleep_time)


class CacheDict:
    lock = threading.RLock()

    def __init__(self, validation_func, sleep_time, back_up_dict=None):
        self.dict = back_up_dict if back_up_dict else dict()
        if not callable(validation_func):
            raise TypeError('Callable object must be passed')
        self.is_valid = validation_func
        self.dispatcher = CacheDispatcher(self.validate_cache, sleep_time)
        self.dispatcher.thread.start()

    def __str__(self):
        return str(self.dict)

    def __repr__(self):
        return str(self.dict)

    @locking(lock)
    def __contains__(self, item):
        return self.dict.__contains__(item)

    @locking(lock)
    def __getitem__(self, key):
        try:
            return self.dict[key]
        except KeyError:
            return None

    @locking(lock)
    def __setitem__(self, key, value):
        self.dict[key] = value

    @locking(lock)
    def keys(self):
        return self.dict.keys()

    @locking(lock)
    def validate_cache(self):
        keys = list(self.keys())
        for key in keys:
            if not self.is_valid(self[key]):
                self.dict.pop(key)


class CacheArray:
    lock = threading.RLock()

    def __init__(self, validation_func, sleep_time, back_up_array=None):
        self.array = back_up_array if back_up_array else []
        if not callable(validation_func):
            raise TypeError('Callable object must be passed')
        self.is_valid = validation_func
        self.dispatcher = CacheDispatcher(self.validate_cache, sleep_time)
        self.dispatcher.thread.start()

    def __str__(self):
        return ' ||| '.join(map(str, self.array))

    def __repr__(self):
        return ' ||| '.join(map(str, self.array))

    @locking(lock)
    def __getitem__(self, key):
        success = False
        for item in self.array:
            if item[0] == key:
                success = True
                yield item[1]
        if not success:
            return None

    @locking(lock)
    def __setitem__(self, key, value):
        self.array.append((key, value))

    @locking(lock)
    def validate_cache(self):
        new_array = []
        for item in self.array:
            if self.is_valid(item[1]):
                new_array.append(item)
        self.array = new_array


def validate(entry):
    import datetime
    time_ = datetime.datetime.today().second
    print(time_, entry[1])
    if time_ > entry[1] + 2:
        return False
    return True


def main():
    cache = CacheArray(lambda x: False, 1)
    cache[1] = 1
    cache[2] = 2
    print(cache)
    time.sleep(2.5)
    print(cache)


if __name__ == '__main__':
    main()
