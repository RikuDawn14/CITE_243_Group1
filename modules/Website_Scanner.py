# modules/website_scanner.py

from PySide6 import QtWidgets, QtCore
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
from thread_worker import Worker

def get_metadata():
    return {
        "name": "Website Scanner",
        "description": "Scan site for broken links, images, and header tags."
    }

### Function to check for all <a> tags and check status ###
def scan_broken_links(url, progress_callback=None):
    output = [] # broken links
    seen = [] # good links

    try: # try to connect to the input webpage and return an error if unable
        base = requests.get(url, timeout=10)
    except Exception:
        return "Could not reach URL."

    soup = BeautifulSoup(base.text, "html.parser")
    links = soup.find_all("a") # find all <a> tags
    total_links = len(links)

    # Calculate total links and send initial progress message
    if progress_callback:
        progress_callback(f"Found {total_links} links to check...\n")

    for idx, link in enumerate(links, 1): # for loop to check if <a> tag has a href attribute
        href = link.get("href") # get the URL from the attribute
        if not href:
            continue

        full = urljoin(url, href) # join URL and href to get full URL
        if full in seen: # if loop to create list of all URLs skipping to next link if not unique
            continue
        seen.append(full)

        # Send progress update showing which link we're checking
        if progress_callback:
            progress_callback(f"Checking link {idx}/{total_links}: {full[:60]}...\n")

        try: # try/except for if the URL does not load
            r = requests.get(full, timeout=10)
            if r.status_code >= 400:
                output.append(f"Broken: {full} (Status {r.status_code})")
        except Exception:
            output.append(f"Broken: {full} (No response)")
            # Notify user immediately when link fails
            if progress_callback:
                progress_callback(f"BROKEN (No response)\n")

    if not output: # if not errors print this
        return "No broken links found."

    return "\n".join(output) # print this if there were errors found

### Function to get URLs for images from webpage ###
def scan_images(url, progress_callback=None):
    output = [] # list of missing images
    seen = [] # list of found image URLs

    try: # try to connect to the input webpage and return an error if unable
        base = requests.get(url, timeout=10)
    except Exception:
        return "Could not reach URL."

    soup = BeautifulSoup(base.text, "html.parser")
    images = soup.find_all("img") # find all image tags
    total_images = len(images)

    # Calculate total images and send initial progress message
    if progress_callback:
        progress_callback(f"Found {total_images} images to check...\n")
    
    for idx, img in enumerate(images, 1): # for loop to get the source information from the HTML
        src = img.get("src")
        if not src:
            continue

        full = urljoin(url, src) # combine the url and the src info
        if full in seen:
            continue
        seen.append(full) # add new full/src to list

        # Send progress update showing which image we're checking
        if progress_callback:
            progress_callback(f"Checking image {idx}/{total_images}: {full[:60]}...\n")

        try: # try/except for if the full/src URL does not load
            r = requests.get(full, timeout=10)
            if r.status_code >= 400:
                output.append(f"Missing image: {full} (Status {r.status_code})")
        except Exception:
            output.append(f"Missing image: {full} (No response)")

    if not output: # if no missing images return this
        return "No missing images.\nFound image URL's:\n" + "\n".join(seen)
    # If there were missing images return this instead
    return "Missing the following images:\n" + "\n".join(output) + "Found image URL's:\n" + "\n".join(seen)

### Function to find H1-3 HTML headings and the text for those headings ###
def scan_headings(url, progress_callback=None):
    
    try:# try to connect to the input webpage and return an error if unable
        r = requests.get(url, timeout=10)
    except Exception:
        return "Could not reach URL."

    # Send initial progress message
    if progress_callback:
        progress_callback("Fetching page and analyzing headings...\n")

    soup = BeautifulSoup(r.text, "html.parser")
    # Get all heading info for each heading type
    h1_tags = soup.find_all("h1")
    h2_tags = soup.find_all("h2")
    h3_tags = soup.find_all("h3")
    # Get number of each heading type
    h1 = len(h1_tags)
    h2 = len(h2_tags)
    h3 = len(h3_tags)

    out = [] # list of headings type and amount
    out.append(f"H1 count: {h1}")
    out.append(f"H2 count: {h2}")
    out.append(f"H3 count: {h3}")

    if h1 == 0:
        out.append("WARNING: No H1 tag found.")
    elif h1 > 1:
        out.append(f"WARNING: Multiple H1 tags found [{h1}]. Best practice is to use only one H1 per page.")
    
    if h1 > 0: # Extract and display H1 text
        out.append("\nH1 Tags:")
        for i, tag in enumerate(h1_tags, 1):
            text = tag.get_text(strip=True)
            out.append(f"  {i}. {text}")
    
    if h2 > 0: # Extract and display H2 text
        out.append("\nH2 Tags:")
        for i, tag in enumerate(h2_tags, 1):
            text = tag.get_text(strip=True)
            out.append(f"  {i}. {text}")
    
    if h3 > 0: # Extract and display H3 text
        out.append("\nH3 Tags:")
        for i, tag in enumerate(h3_tags, 1):
            text = tag.get_text(strip=True)
            out.append(f"  {i}. {text}")

    return "\n".join(out)

### Function that combines all previous functions into one ###
def scan_full(url, progress_callback=None):
    parts = []
    # Send initial progress message for full scan
    if progress_callback:
        progress_callback("=== Starting Full Scan ===\n\n")
    parts.append("=== Broken Links ===")
    if progress_callback:
        progress_callback("Scanning for broken links...\n")
    parts.append(scan_broken_links(url, progress_callback))
    parts.append("")
    parts.append("=== Images ===")
    if progress_callback:
        progress_callback("\n=== Scanning Images ===\n")
    parts.append(scan_images(url, progress_callback))
    parts.append("")
    parts.append("=== Headers ===")
    if progress_callback:
        progress_callback("\n=== Scanning Headers ===\n")
    parts.append(scan_headings(url, progress_callback))
    if progress_callback:
        progress_callback("\n=== Scan Complete ===\n")
    return "\n".join(parts)

def create_module(parent=None):
    widget = QtWidgets.QWidget(parent)
    widget.thread_pool = []  # REQUIRED TO PREVENT QTHREAD DESTRUCTION
    layout = QtWidgets.QVBoxLayout(widget)

    # URL input
    row = QtWidgets.QHBoxLayout()
    url_label = QtWidgets.QLabel("Enter URL:")
    url_input = QtWidgets.QLineEdit()
    row.addWidget(url_label)
    row.addWidget(url_input)
    layout.addLayout(row)

    # Buttons
    btn_row = QtWidgets.QHBoxLayout()
    btn_links = QtWidgets.QPushButton("Scan Broken Links")
    btn_imgs = QtWidgets.QPushButton("Scan Images")
    btn_headers = QtWidgets.QPushButton("Scan Headings")
    btn_full = QtWidgets.QPushButton("Full Scan")

    btn_row.addWidget(btn_links)
    btn_row.addWidget(btn_imgs)
    btn_row.addWidget(btn_headers)
    btn_row.addWidget(btn_full)
    layout.addLayout(btn_row)

    # Results
    results = QtWidgets.QTextEdit()
    results.setReadOnly(True)
    layout.addWidget(results)

    def run_thread(fn):
        url = url_input.text().strip()
        if not url:
            results.setPlainText("Enter a valid URL.")
            return

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        results.clear()
        results.append("Scanning...")

        worker = Worker(fn, url)
        thread = QtCore.QThread()

        worker.moveToThread(thread)

        worker.progress.connect(lambda msg: results.append(msg))

        worker.finished.connect(lambda msg: results.append(f"\n{'='*50}\nFINAL RESULTS:\n{'='*50}\n{msg}"))
        worker.error.connect(lambda msg: results.append(f"\nERROR: {msg}"))

        # worker.finished.connect(thread.quit)
        # worker.error.connect(thread.quit)

        # thread.finished.connect(worker.deleteLater)
        # thread.finished.connect(thread.deleteLater)

        thread.started.connect(worker.run)

        widget.thread_pool.append((thread, worker))  # KEEP THREAD ALIVE
        thread.start()

    btn_links.clicked.connect(lambda: run_thread(scan_broken_links))
    btn_imgs.clicked.connect(lambda: run_thread(scan_images))
    btn_headers.clicked.connect(lambda: run_thread(scan_headings))
    btn_full.clicked.connect(lambda: run_thread(scan_full))

    return widget

### Used for testing functions within this file if run independent ###
# comment out 'from thread_worker import Worker' before testing
if __name__ == "__main__":
    url = "https://www.nic.edu" 
    # uncomment desired function test
    # Simple progress callback for console testing
    def print_progress(msg):
        print(msg, end='')
    
    # Test with progress updates
    #print(scan_images(url, print_progress))
    print(scan_broken_links(url, print_progress))
    #print(scan_headings(url, print_progress))
    #print(scan_full(url, print_progress))