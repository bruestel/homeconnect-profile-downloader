# Home Connect Profile Downloader

This tool fetches profile information for all Home Connect devices linked to your account, enabling direct communication with your appliances over the local network.

![Screenshot Home Connect Profile Downloader UI](doc/screenshot.png "Main UI")

## Why Use This Tool?

With the gathered profile information, you can directly communicate with your Home Connect devices within your home network. This is particularly useful for integrations such as the [Home Connect Direct binding for openHAB](https://community.openhab.org/t/home-connect-direct-binding-no-cloud/160857/36).

## Run it

> **Note:** Please ensure you download the correct package file for your system architecture. Use files labeled `amd64`, `x86_64` or `x64` for 64-bit x86 systems, and files labeled `arm64` for 64-bit ARM-based systems.

### On Linux

#### For RPM-Based Systems

Use the `rpm` command to install the package on RPM-based distributions such as RHEL, CentOS, Fedora, or openSUSE.

1. Download rpm file.
2. Open a terminal and navigate to the file you have downloaded.
3. Run the following command, replacing `homeconnect-profile-downloader_<version>_<amd64|arm64>.rpm` with the target architecture and version in the file name:  
   ```bash
   rpm -i homeconnect-profile-downloader_0.9.0_amd64.rpm
   ```
4. Start the application (`homeconnect-profile-downloader`)

#### For DEB-Based Systems

Use the dpkg command to install the package on DEB-based distributions such as Debian, Ubuntu, or Linux Mint.

1. Download dep file.
2. Open a terminal and navigate to the file you have downloaded.
3. Run the following command, replacing `homeconnect-profile-downloader_<version>_<amd64|arm64>.deb` with the target architecture and version in the file name:  
   ```bash
   dpkg -i homeconnect-profile-downloader_0.9.0_amd64.deb
   ```
4. Start the application (`homeconnect-profile-downloader`)


#### For AppImage

The AppImage format allows you to run the application without installation. It is a portable and self-contained executable.

1. Download AppImage file.
2. Open a terminal and navigate to the file you have downloaded.
3. Navigate to the directory containing the .AppImage file.
4. Make the AppImage executable by running: `chmod +x <package-name>.AppImage`
5. Run the AppImage: `./<package-name>.AppImage`

### On Windows

To install and run the application on Windows, follow these steps:

1. Download the ZIP file (e.g. `homeconnect-profile-downloader-win32-x64-0.9.0.zip`)
2. Extract the ZIP file  
   - Navigate to the location where the `.zip` file was downloaded.
   - Right-click on the `.zip` file and select **Extract All...**.
   - Choose a destination folder and click **Extract**.

3. Run the application  
   - Open the folder where the files were extracted.
   - Locate the application executable file (e.g., `homeconnect-profile-downloader.exe`).
   - Double-click the `.exe` file to run the application.
   - Unsigned Application Warning: When running the application, Windows Defender SmartScreen may display a warning that the file could be dangerous because it is not digitally signed.  
      - This warning can be safely ignored.  
      - To proceed:
        1. Click **More info** on the warning message.
        2. Select **Run anyway** to start the application.

### On Mac OS

#### Running the Pre-built Application

When you download a pre-built application from the releases, macOS may prevent it from running because it is not from a registered developer. If you see an error message, you can resolve this by removing the "quarantine" attribute that macOS adds to downloaded files.

1.  After downloading and unzipping the application, if you see an error message when trying to open it, click **Cancel**.
2.  Open the **Terminal** app (you can find it using Spotlight with `Cmd + Space`).
3.  Type the command `xattr -cr ` (note the space at the end) but do not press Enter yet.
4.  Drag the application file (e.g., `homeconnect-profile-downloader.app`) from your Finder window into the Terminal window. The path to the app will be automatically appended to your command.
5.  The full command will look something like this: `xattr -cr /Users/YourName/Downloads/homeconnect-profile-downloader.app`
6.  Press **Enter** to run the command.
7.  You should now be able to open the application by double-clicking it.

#### Building and Running from Source (Alternative Method)

If you prefer, you can build and run the application locally from the source code.

1.  **Install Node.js and npm**
    *   Ensure you have Homebrew installed. If not, follow the instructions at [brew.sh](https://brew.sh).
    *   Install Node.js (version 22) and npm:
        ```bash
        brew install node@22
        ```
    *   Follow any post-installation instructions from Homebrew and then open a new terminal window.
    *   Verify the installation:
        ```bash
        node -v
        npm -v
        ```

2.  **Clone the Repository**
    ```bash
    git clone https://github.com/bruestel/homeconnect-profile-downloader.git
    ```

3.  **Navigate to the Project Directory**
    ```bash
    cd homeconnect-profile-downloader
    ```

4.  **Install Dependencies**
    ```bash
    npm install
    ```

5.  **Run the Application**
    ```bash
    npm start
    ```

## Build and Run

### Prerequisites

Ensure that you have [Node.js](https://nodejs.org/) 22+ installed on your system. You can verify this by running the following commands in your terminal:

```bash
node -v
npm -v
```
If these commands return a version number, Node.js and npm are installed. Otherwise, follow the [Node.js installation guide](https://nodejs.org/en/download/package-manager) to set it up.

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/bruestel/homeconnect-profile-downloader.git
   ```
2. Install dependencies:
   ```bash
   cd homeconnect-profile-downloader
   npm install
   ```
3. Start the application:
   ```bash
   npm start
   ```
