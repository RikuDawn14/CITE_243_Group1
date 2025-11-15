# Documentation from Matthew

### Friday Nov 14, 2025
- I cleaned up the repository and created the first release of the project `v0.1.0-alpha` 
- I tested all modules individually for functionality and all returned results in line with expectations.
- Bugs I have found are that when trying to run the program as a whole there is an error causing the modules (both vuln_scanner and website_scanner) to quit before they can run making the program seem like it is hanging. However, if run in debug with a breakpoint in the module the program functions as expected. Will need farther investigate the cause of this bug.