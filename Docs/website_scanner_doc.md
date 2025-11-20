# `website_scanner.py` — Module Documentation

## Overview

`website_scanner.py` provides a set of utility functions for scanning websites for:

- **Broken links** (`<a>` tags)
- **Missing / inaccessible images** (`<img>` tags)
- **Heading structure** (`<h1>`, `<h2>`, `<h3>`)
- **All-in-one full scan**

---

## Features

### 1. Broken link scanning

- Checks each hyperlink, fetches the target, and reports links that return error responses or fail to load.

### 2. Image integrity scanning

- Checks image URLs for missing or unreachable image files.

### 3. Heading analysis

- Reports counts and text for `<h1>`, `<h2>`, and `<h3>` tags.
- Includes warnings for missing or multiple `<h1>` tags.

### 4. Full-page scan

- Runs all three scans sequentially and consolidates results.

---

## Installation Requirements
- Python 3.13.7
- Imported libraries `pip install requirements.txt -r`

---

## Function Reference

### `get_metadata()`

Returns module metadata for integration in the larger system.

```python
{
    "name": "Website Scanner",
    "description": "Scan site for broken links, images, and header tags."
}
```

---

## 1. Broken Link Scanner

Scans all `<a>` tags, extracts URLs, resolves them to absolute paths, and checks their HTTP status.

#### **Arguments**

| Name                | Type                 | Description                                                     |
| ------------------- | -------------------- | --------------------------------------------------------------- |
| `url`               | `str`                | The webpage to scan. Must be reachable.                         |
| `progress_callback` | `callable` or `None` | Optional function accepting status text as scanning progresses. |

#### **Returns**

A `str` containing:

- A list of broken links **or**
- `"No broken links found."` if everything is valid
- `"Could not reach URL."` if the main page cannot be downloaded

---

## 2. Image Scanner

Finds `<img>` tags, resolves their `src` attributes, and checks whether the image URLs return a valid HTTP response.

#### **Returns**

- `"No missing images. Found image URL's:..."`
if all images load
- `"Missing the following images:..."`
if some fail to load
- `"Could not reach URL."`
if the page cannot be accessed

---

## 3. Heading Scanner

Extracts `<h1>`, `<h2>`, and `<h3>` tags, returning:

- Counts for each heading type
- A list of each heading’s text
- Warnings for:
    - Missing `<h1>`
    - More than one `<h1>`

---

## 4. Full Website Scan

Runs:

1. Broken link scan
2. Image scan
3. Heading scan

Results are combined into one output string.

---

## GUI Integration

Creates and returns a PySide6 `QWidget` containing:

- A URL input field
- Buttons for:
    - Broken links scan
    - Images scan
    - Headings scan
    - Full scan
- A scrolling results pane
- Threaded execution for all tasks
    (Prevents UI freezing)

---

## Command-Line Testing

Inside the file, a `if __name__ == "__main__":` block allows local testing:

```bash
python3 website_scanner.py
```

You can uncomment any of the test calls to try individual scanners.

---

## Notes & Best Practices

- **Timeouts:** All HTTP requests use a 10-second timeout to avoid indefinite waiting.
- **Duplicate URLs:** The scanner skips repeated URLs to reduce unnecessary requests.
- **Progress Callback:** Any callable can be used for progress reporting, including GUI elements or simple `print`.
- **Threading:** When used in the GUI, all scans run in the background using the imported `Worker` class.

---

Work on by: [Rikudawn](https://github.com/RikuDawn14) (Matthew Balthaser)