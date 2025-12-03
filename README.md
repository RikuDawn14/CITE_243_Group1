# Python Group 1 Project
---
## This is the repository for Group 1 in North Idaho College CITE-243
![nic logo](https://www.nic.edu/media/nic-main/branding/logos/190211-NIC-Mountain-v1---RGB-02.png)
---
## Team members
- Philip - Project Manager
- Cole - Dev 1
- Noah - Tester
- Matthew - Dev 2
___

# Project description
This is a basic vulnerability scanner designed to test ports, run a vulnerability scan on any site, and also to check any broken links, missing photos, or missing headers on a site. The port scanner is able to scan a range of specified ports as well as the host computer. It also has a built in gateway scanner, service detection, banner grabbing, and OS fingerprinting. You can also alter how many threads to use in order to speed up the scan time. There is also some preset port ranges already set (Well-Known, Registered, All Ports). The scan results can be exported as a TXT, CSV, or JSON file. We also have a vulnerability recommendations to recommend  changes based on the missing security headers. The Vulnerability scanner will check the security headers, SSL certificates, as well as a basic port probe. We also have a website scanner to check for any broken links, scan any images on the site, as well as scan the headers for that site. You can use either an IP or hostname for all modules. 

---

# Technologies Used

This project is built on a collection of Python libraries that provide functionality for GUI development, web scraping, HTTP communication, PDF processing, and utility features. Below is a categorized list of all technologies used, based on the dependency list.

---

## Python Language Features

### Dataclasses and Typing
- dataclasses — provides the @dataclass decorator for structured data models.  
- typing — core Python typing support for static type hints.  
- typing_extensions — backports and experimental typing features not in the standard library.


---

## Web Scraping and HTML Parsing

### BeautifulSoup4 and Soupsieve
- beautifulsoup4 — parses HTML/XML content for scraping or structured data extraction.  
- soupsieve — enables advanced CSS selector-based searches within BeautifulSoup.


---

## HTTP and Networking Stack

These libraries collectively support making robust and secure HTTP requests.

- requests — primary HTTP client library for sending GET/POST requests.  
- urllib3 — low-level HTTP library used internally by requests.  
- certifi — provides up-to-date root certificates for SSL/TLS verification.  
- charset-normalizer — handles detection and normalization of text encoding.  
- idna — manages Internationalized Domain Names.


---

## PDF Processing

- pypdf — library for reading, parsing, splitting, and manipulating PDF documents.

---

## Graphical User Interface (GUI)

This project uses Qt for the graphical interface through Python bindings.

- PySide6 — official Qt6 Python bindings (widgets, windows, layouts).  
- PySide6_Essentials — core Qt modules for the PySide runtime.  
- PySide6_Addons — additional Qt modules beyond core essentials.  
- shiboken6 — binding generator and runtime support for PySide6.


---

## Progress and User Feedback

- tqdm — provides progress bars for loops or long-running operations.

---

## Import and Package Utilities

- importlib — advanced import functionality, often used for dynamic module loading.

---

## Summary of Role Categories

| Category | Technologies |
|---------|--------------|
| GUI Framework | PySide6, PySide6_Essentials, PySide6_Addons, shiboken6 |
| Web Scraping | beautifulsoup4, soupsieve |
| Networking / HTTP | requests, urllib3, certifi, charset-normalizer, idna |
| PDF Processing | pypdf |
| Type System / Data Models | dataclasses, typing, typing_extensions |
| Utilities | tqdm, importlib |

---

# Instructions to run the program
## Source Code
### Install Prerequisites
If running source code, just run the Groupproject.py file, this is the main entry point for the program.
Change in to resources directory and paste in the command below. 
#### pip install -r requirements.txt

## Using EXE
Just run the exe, easy as that. 



# Role breakdown and contributions
## Team members
### Philip - Project Manager

### Noah - Tester
Did the general testing. Found some bugs and opened issues on those bugs, as well as coming up with some new features that would be nice. Some quality of life changes as well were implemented because of some findings. I updated this README.md to add the program description, how to use, and instructions to run the program. Biggest contribution was the bug testing and weird edge case that were found. Those can be found in the [Noah_Docs.md](https://github.com/RikuDawn14/CITE_243_Group1/blob/main/Docs/Noah_Docs.md).  I also got the exe all built and ready to go. The .spec file is used to tell pyinstaller how to pull the modules and where they are in the code. I also had to change a module used in the main file to dynamically build the paths for the modules (more in my Docs). 

### Cole - Dev 1


### Matthew - Dev 2

