# VirusBytes - Open Source Antivirus
VirusBytes is a Python-based desktop application. Follow these steps to install and run it on your system. It has been tested on Windows 11 and Ubuntu 24.04 , but it should work on Linux and macOS with minor adjustments.
# Website
www.virusbytes.com

<img src="https://github.com/sourcecode347/VirusBytes/blob/main/img/VirusBytesScan.png" style="width:100%;height:auto;"/>

# Prerequisites

Python 3.8 or higher (Download from <a href="https://python.org/donloads">python.org</a>).

Download and exctract <a href="https://virusbutes.com/VirusBytes.zip">VirusBytes</a>.

# Step 1: Install Python

Ensure Python is installed.Don't forget to check "ADD python.exe to PATH" on Python Installation.

Open a terminal or command prompt and check:

    python --version

If not installed, download and install from the official website. Make sure to add Python to your PATH during installation.

# Step 2: Install Required Libraries
On Windows VirusBytes depends on several Python libraries. Install them using pip:

    pip install watchdog psutil requests gputil setuptools Pillow olefile pywin32 matplotlib

On Linux install Dependencies :

    sudo apt install python3-tk python3-watchdog python3-psutil python3-pil python3-pil.imagetk python3-matplotlib

# Step 3: Download the VirusBytes Script
Download the <a href="https://virusbytes.com/VirusBytes.zip">VirusBytes</a>

Save it in a directory, e.g., C:\VirusBytes on Windows.

# Step 4: Prepare the Icon (Optional)
The application uses an icon file at img/VirusBytes.png relative to the script directory. Create a folder named "img" in the script directory and place a PNG image there, or the app will use a default red square.

# Step 5: Run the Application
Open a command prompt in the script directory and run:

    python VirusBytes.py

On Windows, you can create a shortcut or batch file for easier access.

# Step 6: Update Virus Database
Download the <a href="https://virusbytes.com/VirusBytesDatabase.cvd">VirusBytesDatabase.cvd</a>

And import it to VirusBytes , wait for this action , it takes some time.

# Step 7: Configure Auto-Start (Optional)
In the app's Settings tab, enable "Start with Windows (Registry)" to add it to startup.

# Step 8: Support This Project
Make a <a href="https://buy.stripe.com/fZu28keQj5Um1Yk6P01gs00">Donation</a> to support this Open Source Project.

# Step 9: Use The VirusBytes Command Line Interface - Cross Platform ( Only Terminal )
Download and Exctract the <a href="https://virusbytes.com/VirusBytesCLI.zip">VirusBytesCLI</a>

Run the following command for informations

    python VirusBytesCLI.py --help

<img src="https://github.com/sourcecode347/VirusBytes/blob/main/img/VirusBytesCLI.png" style="width:100%;height:auto;"/>

# Usage Instructions</h2>
VirusBytes provides a GUI with multiple tabs for dashboard, scanning, quarantine, monitoring, and settings.

  # Dashboard Tab
  <ul>
      <li>Displays threats blocked, last scan time.</li>
      <li>Buttons to view and clear reports.</li>
      <li>Donate link.</li>
  </ul>

  # Scan Tab
  <ul>
      <li>Update database links for VirusBytes and ClamAV.</li>
      <li>Import database from CVD, TXT, or PKL files.</li>
      <li>Export database to CVD or PKL.</li>
      <li>Scan a folder, pause/cancel scan.</li>
      <li>View scan progress and results.</li>
      <li>Actions: Delete selected/all detections, extract detections to TXT, remove hash from DB, check selected on virustotal.</li>
  </ul>

  # Quarantine Tab</h3>
  <ul>
      <li>List of quarantined files.</li>
      <li>Restore or delete selected files.</li>
  </ul>

  # Monitoring Tab</h3>
  <ul>
      <li>Real-time system monitoring: CPU, RAM, Disk, GPU, Network, Battery.</li>
      <li>Displays usage with progress circles and graphs.</li>
  </ul>

  # Settings Tab
  <ul>
      <li>Toggle real-time protection (monitors folders for changes).</li>
      <li>Toggle web protection (blocks malicious URLs).</li>
      <li>Toggle auto-start.</li>
      <li>Update malicious URLs database.</li>
      <li>Add/remove monitored folders.</li>
  </ul>

  # Additional Features
  <ul>
      <li>Real-time file scanning on creation/modification in monitored folders.</li>
      <li>Web URL checking for malicious sites and SSL validity.</li>
      <li>Quarantine management: Files are renamed and moved to quarantine folder.</li>
      <li>Reports: View JSON reports of actions.</li>
  </ul>

  # Troubleshooting
  <ul>
      <li>Check logs in the terminal for debug info (logging level DEBUG).</li>
      <li>Ensure all libraries are installed if errors occur.</li>
      <li>For Windows registry issues, run as administrator.</li>
      <li>If icon not found, create img folder with VirusBytes.png.</li>
  </ul>

  For more details or issues, check the source code comments or contact the developer.
