# Documentation from Matthew

### Friday Nov 14, 2025 (1)
- I cleaned up the repository and created the first release of the project `v0.1.0-alpha` 
- I tested all modules individually for functionality and all returned results in line with expectations.
- Bugs I have found are that when trying to run the program as a whole there is an error causing the modules (both vuln_scanner and website_scanner) to quit before they can run making the program seem like it is hanging. However, if run in debug with a breakpoint in the module the program functions as expected. Will need farther investigate the cause of this bug.

### Friday Nov 14, 2025 (2)
- Fixed bug in vuln_scanner and website_scanner.
- Original code
```     
worker = Worker(fn, target)
thread = QtCore.QThread()
worker.moveToThread(thread)

worker.finished.connect(out_box.setPlainText)
worker.error.connect(out_box.setPlainText)

worker.finished.connect(thread.quit)
worker.error.connect(thread.quit)

thread.finished.connect(worker.deleteLater)
thread.finished.connect(thread.deleteLater)

thread.started.connect(worker.run)

widget.thread_pool.append(thread)
thread.start()
```
- Updated code
```     
worker = Worker(fn, target)
thread = QtCore.QThread()
worker.moveToThread(thread)

worker.finished.connect(out_box.setPlainText)
worker.error.connect(out_box.setPlainText)

worker.finished.connect(thread.quit)
worker.error.connect(thread.quit)

thread.finished.connect(worker.deleteLater)
thread.finished.connect(thread.deleteLater)

thread.started.connect(worker.run)

widget.thread_pool.append((thread, worker))
thread.start()
```
- Python was garbage collecting the local variable worker but Qt still needed it. Adding it to the `widget.thread_pool.append(thread)` allowed the variable to persist.
- The reason it worked in debug was because debug kept the local variables longer allowing the program to run.