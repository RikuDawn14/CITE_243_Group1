# Documentation from Matthew
![profile pic](https://raw.githubusercontent.com/RikuDawn14/CITE243Python/refs/heads/main/wallpaper.png)
___
### Friday Nov 14, 2025 (1)
- I cleaned up the repository and created the first release of the project `v0.1.0-alpha` 
- I tested all modules individually for functionality and all returned results in line with expectations.
- Bugs I have found are that when trying to run the program as a whole there is an error causing the modules (both vuln_scanner and website_scanner) to quit before they can runbut after the `Scanning...` is printed, making the program seem like it is hanging. However, if run in debug with a breakpoint in the module, the program functions as expected. Will need to farther investigate the cause of this bug.
---
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
- Python was garbage collecting the local variable `worker` but Qt still needed it. Adding it to the `widget.thread_pool.append(thread)` allowed the variable to persist.
- The reason it worked in debug was because debug kept the local variables longer allowing the program to run.
- Created new release with this bug fix. `v0.1.1-alpha`
---
### Saturday Nov 15, 2025
- Added some extra functionality to the `scan_headings` function.
- Changed output of the `scan_images` function to include found image URLs.
- Added comments to the `Website_Scanner.py` module to explain what is happening during the functions.
---
### Friday Nov 21, 2025
#### Addressing Issues from [Issue #50](https://github.com/RikuDawn14/CITE_243_Group1/issues/50)
##### Formatting Issue
- Added `\n` to that messaging to move the next line, fixing this formatting issue. 
##### Sub Directory Bug
- Added a function to do the URL validation to clean up repeated code.
- This also allowed for easy addition of a error message of invalid URL entries.
##### Rapid Input Bug
- Added a disable of the button in the module while a script is running. After script is done the buttons are reenabled.

***NOTE:** These changes were only done to `website_scanner.py` as `vuln_scanner.py` not actively being worked on by me, but could be easy to copy over if needed.*