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


class CacheDictDispatcher:
    def __init__(self, func, sleep_time):
        self.thread = threading.Thread(target=self.start_validation, args=(func, sleep_time))
        self.stop = False

    def start_validation(self, func, sleep_time):
        while True:
            if self.stop:
                break
            func()
            time.sleep(sleep_time)


class CacheDict:
    lock = threading.RLock()

    def __init__(self, validation_func, sleep_time, back_up_dict=None):
        self.dict = back_up_dict if back_up_dict else dict()
        if not callable(validation_func):
            raise TypeError('Callable object must be passed')
        self.is_valid = validation_func
        self.dispatcher = CacheDictDispatcher(self.validate_cache, sleep_time)
        self.dispatcher.thread.start()

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


def validate(entry):
    import datetime
    time_ = datetime.datetime.today().second
    print(time_, entry[1])
    if time_ > entry[1] + 2:
        return False
    return True


def main():
    print(CacheDict(lambda x: True, 5))


if __name__ == '__main__':
    main()
