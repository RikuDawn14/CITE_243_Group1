# 11/16/25

## General Ideas

Check for a comma in the URL, it's an easy typo. It would be nice if that were pointed out to the user when they input a comma instead of a period.

If I click Scan Headers and then immediately click Scan Images, there is no indication which one is actually running. Other observation: When you click multiple buttons one after another, the outputs will show all clicked. 

For example:
		
If I click Scan Broken Links, then Scan Images, then Scan Headings all right after another, the output goes in that same order. Sometimes it will show the reverse order as well. It would be nice if it took only your last input and used that as the final choice. If you click the buttons too fast, one after another, it may not register the last click from the looks of it.

## Vulnerability Scanner

### Port Probe

I inputted 8.8.8.8 into Port Probe and get results. If you just add a .8 to the end of that and re-press the button, all the ports just change to closed, it doesn't seem to try to reconnect for some reason. If I give it bogus input (asdfe), it returns all closed ports. 

Port Probe does work on LAN services and IPs. I manually added port 53 in the code for testing pihole on my LAN, and it did pick 53 up as open. The main issue for Port Probe it that it doesn't detect an invalid IP, it just shows all as closed.

### Full Scan

Full Scan - If I do the same thing (above) for the Full Scan, the fingerprinting returns expected (Could not connect to server.) SSL returns expected (kk failed: [Errno 11001] getaddrinfo failed). Port Probe has the same issue, it says all ports are closed even though the address is invalid.

## Website Scanner

### Scan Broken Links

Tried google.com, it worked, but the resulting URL it says it checks is http://google.com, NOT https. This seems to be the case for every site. The browser will automatically upgrade to https, so not a huge deal if you copy and paste that link. If you manually put https:// then the output will have https://, but only if you specify in the input. 

### Full Scan

When inputting a valid URL (youtube.com), I get "name 'scan_headers' is not defined" as the output. I tried Google.com and got the same thing. When I first press Full Scan with a good url, it does say Scanning... | This may take a while. It does this before the scan_headers output. I tried 1.1.1.1 and got the exact same output. Scanning... and then scan_headers is the result. 

First output for Website Scanner > Full Scan
<!--No_Progress-->
![No Progress](Noah_Docs_Images/No_Progress.png)

name 'scan_headers' is not defined pictured below
<!--Scan_Headers-->
![Scan Headers](Noah_Docs_Images/Scan_Headers.png)


These screenshots were taken about 5 seconds apart.
I need to test more edge cases here soon.

# 11/17/25

## Fixed Some Bugs

I fixed the Port Probe bug we had. All I had to do was add a try/except clause to test the connection right after the function was called. It was very simple as we had used the same try/except clause in other modules to prevent this bug. Here are the few lines of code I added below:
```python
try:
    r = requests.get(url, timeout=10)
except Exception:
    return "Could not connect to server."
```

Matthew also fixed the Scan Headers bug as. That feature now works as expected. 

# 11/18/25

## More Testing

###  Patch 5

I just tried Patch 5, and the Vulnerability Scanner doesn't work. If I put in anything at all, I get the following:

| Quick Scan                                                                  | SSL Check                                                          | Port Probe                                                          | Full Scan                                                          |
|-----------------------------------------------------------------------------|--------------------------------------------------------------------|---------------------------------------------------------------------|--------------------------------------------------------------------|
| fingerprint_server() got an unexpected keyword argument 'progress_callback' | ssl_check() got an unexpected keyword argument 'progress_callback' | port_probe() got an unexpected keyword argument 'progress_callback' | full_scan() got an unexpected keyword argument 'progress_callback' |

I re-ran the requirements.txt in case there were any changes as well.

### Website Scanner

You are now able to see progress as the program checks through the different subdomains. This is a nice addition.


# 11/20/25
## Patch 6
### Minor Formatting Bug
There's a minor formatting bug when there is a missing image. The 'status 404' message is butted right up against the 'Found image URL' message. There should be a space or a newline between the two.
  
Image below:
<!--Formatting-->
![Formatting Screenshot](Noah_Docs_Images/Formatting.png)

This also appears in the Full Scan output when an image is missing, as it calls the same function.

### Bogus Directory Bug

For both modules, if you put a valid domain name (google.com) but an invalid subdirectory (google.com/.,.asoea.a,f#%^*(@^#), the program will still run and return results. It would be better if it returned an error message saying the URL is invalid or could not be reached. This could simulate false positives if a user is trying to scan a specific directory that doesn't exist (easy typos return the exact same results).

Image below:
<!--Bogus Direcory-->
![Bogus Directory](Noah_Docs_Images/Bogus_Directory.png)

### Rapid Input Bug

While rapidly clicking Quick Scan, it registers multiple inputs. For example, I spam clicked Quick Scan 3 times in a row, and it ran the scan 3 times, returning 3 sets of results. It would be better if it only registered the last click or disabled the button while a scan is running. The output is the same for every scan, it just duplicates the results.

Image below (notice the scrollbar) :
<!--Rapid_Input-->
![Rapid Input](Noah_Docs_Images/Rapid_Input.png)

I could get this to happen with the following buttons:
### Vulnerability Scanner
**Quick Scan**\
**SSL Check**\
**Port Probe**\
**Full Scan**
### Website Scanner
**Scan Broken Links**\
&nbsp;&nbsp;&nbsp;(*This was especially bad because I tried google.com, which has 17 links to check. It tried all 17 a total of 7 times. It was very slow*)\
**Scan Images**\
**Scan Headings**\
**Full Scan**\
&nbsp;&nbsp;&nbsp;(*This was also especially bad because it ran all 3 scans multiple times. It was very slow as well.*)

## Conclusion for Rapid Input Bug
It happens on every button in both modules. It would be best to disable the buttons while a scan is running to prevent this from happening.

# 11/21/25
## Patch 7
*Some fixes may only be implemented into the Vulnerability Scanner module at this stage, but they are easily ported to the other module when fully completed* 
### Minor Formatting Bug Fix
This is now fixed. A newline was added between the 'status 404' message and the 'Found image URL' message.

### Bogus Directory Bug Fix
This is now fixed as well. 

### Rapid Input Bug Fix
This is now fixed. The buttons are disabled while a scan is running, and re-enabled when it is complete.

#### Additional Idea
One new idea to consider it adding a cancel button while the scan is running incase the user would like to stop it whenever needed. For example, I just scanned a website with 30 or so images and it just took a while. You can still click to the other module and use it as normal when the which is nice.

### Weird Crash
I entered  github.com/noahcoook into Web Scanner -> Scan Broken Links, and it instantly crashed. This was after having it open for a while and using the scans many times. I tried on a fresh instance of the program after starting it again, and it didn't crash after handling the same input. There was 113 links to scan, maybe that contributed to it. I had this happen once in Patch 6 after pasting a long URL into the input box for one of the modules. I can't replicate it so, it may be a one-time thing.

# 12/1/25

## EXE Built
I was able to get the exe built with some issues as expected. I had to redo the discover modules function in the main file. This was because pyinstaller kept failing to correctly build the paths to where the modules were located. This caused the program to compile, just with no modules loaded. I also had to create the .spec file to make the compile process a little easier. Before the .spec file, I had to manually use pyinstaller flags to add the modules folder. The .spec file did this for me and shortened the command to build. The command to build, after the cwd is the project folder, is as follows:

``` pyinstaller Groupproject.spec --clean
```
## v1.0
I tested the final version with all my previous finds, and it seems to be working very well. When you stop a scan, it does take a moment to be able to start a scan again, this didn't really affect my experience though. The exe does take a moment to open at first, but this is expected. From all my testing, this realease seem to be solid and working well. 