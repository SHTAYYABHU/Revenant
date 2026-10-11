"""A tiny logger with the methods spiffsgen calls, failing loudly on die."""


class _Log:
    def die(self, message, *args, **kwargs):
        raise RuntimeError(str(message))

    def __getattr__(self, name):
        def emit(message="", *args, **kwargs):
            print(f"spiffsgen {name}: {message}")
        return emit


log = _Log()
