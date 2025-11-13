# thread_worker.py

from PySide6.QtCore import QObject, Signal, Slot

class Worker(QObject):
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kw = kwargs

    @Slot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kw)
            # Ensure result is string
            if result is None:
                result = ""
            self.finished.emit(str(result))
        except Exception as e:
            self.error.emit(str(e))
