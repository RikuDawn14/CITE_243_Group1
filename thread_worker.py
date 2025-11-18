# thread_worker.py

from PySide6.QtCore import QObject, Signal, Slot

class Worker(QObject):
    finished = Signal(str)
    error = Signal(str)
    progress = Signal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kw = kwargs

    @Slot()
    def run(self):
        try:
            result = self.fn(*self.args, progress_callback=self.emit_progress, **self.kw)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
    def emit_progress(self, message):
        # Callback function that scanning functions can call to report progress
        self.progress.emit(message)
