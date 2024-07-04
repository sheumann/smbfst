The SMB FST for GS/OS
=====================
By Stephen Heumann

The SMB FST allows an Apple IIGS to access file servers using the SMB protocol.

System Requirements
-------------------
* An Apple IIGS with System 6.0.1 or later
* [Marinetti][1] 3.0b11 or later
* A Marinetti-compatible network interface (such as an Ethernet card)

If you are using an Uthernet or Uthernet II, please be sure to install the latest version of their Marinetti link layers.

[1]: http://www.apple2.org/marinetti/


Installation
------------
To install the SMB FST:

* Place the `SMB.FST` file in the `*:System:FSTs` folder (where `*` indicates your boot disk).
* Place the `SMB` file in the `*:System:CDevs` folder.

Reboot the system to complete the installation.


Compatibility
-------------
The SMB FST is compatible with Windows, macOS, Samba, Solaris, and illumos file servers. Using a modern, currently-supported version of the server software is strongly recommended. See the Server Configuration section below for information on how to configure these servers to work with the SMB FST.

The SMB FST may also work with other servers that support the SMB 2 or SMB 3 protocols, but they have not been tested.


Connecting to SMB Servers
-------------------------
To connect to an SMB server, open the SMB control panel. You can enter the server address in the text box or select from a list of servers detected on the local network. In some circumstances, servers may not show up in the list, but you can still connect to them by entering their address. Once you have selected a server, click __Connect__.

Once you have connected to a server, you will be prompted to log in. Enter your user name and password. If your account is associated with a domain (used in enterprise Windows networks), enter it as well. When logging in to home systems, the domain can typically be left blank. If you are logging in as a guest, you may need to either enter the name "Guest" or leave the name blank, depending on the server's configuration. There is an option to save your login information for the server, so that you will not need to enter it manually in the future.

Once you have logged in, you will be shown a list of file shares available on the server. Select the ones you want and click __Mount__. The selected shares will be mounted as network disks on your Apple IIGS, and you will be able to access them like other disks, e.g. in the Finder and in the open or save dialogs of applications. There is an option to mount the selected shares every time the IIGS starts up; this is only available if you have saved your login information for the server.

To disconnect from a file share when you are done with it, drag it to the Trash or use the Eject command in the Finder's Disk menu.


Server Configuration
--------------------
The following subsections give instructions for configuring Windows, macOS, Samba, Solaris, or illumos servers for use with the SMB FST, as well as general requirements applicable to any SMB server.

These instructions only cover configuration steps that are specifically necessary to work with the SMB FST. For general instructions on configuring your computer as an SMB server, refer to the documentation for your operating system.


### Windows Server Configuration

Windows servers should typically work without requiring configuration changes, but some adjustments may be helpful.

Some Windows servers may require message signing by default. The SMB FST is compatible with this, but for best performance it should be turned off. To do this, open PowerShell as an administrator and enter the following command:

    Set-SmbServerConfiguration -RequireSecuritySignature $false

Windows does not fully support mDNS-SD by default, so Windows servers will not be listed in the SMB control panel. You can still connect to them by entering their addresses, but if you want them to show up in the list, you should perform the following steps:

1. Go to https://developer.apple.com/bonjour/
2. Download and install the Bonjour SDK for Windows.
3. Open the Windows Control Panel.
4. Open the Bonjour control panel. (You may need to select Large icons or Small icons view to see it.)
5. Enable the option to "Advertise shared folders using Bonjour."

(Bonjour for Windows may also be included with some applications like iTunes, but those versions do not necessarily include the Bonjour control panel. Installing the Bonjour SDK will ensure it is available.)


### macOS Server Configuration

To support logging in using the SMB FST, you must enable "Windows File Sharing" for the account(s) you want to use. You can do this as follows:

1. Open System Settings.
2. Go to the General -> Sharing section.
3. Click the circled `i` by File Sharing.
4. Click __Options...__
5. Under Windows File Sharing, click the check boxes to turn it on for any accounts you want to use from the IIGS, and enter their passwords when prompted.

macOS servers require message signing by default. The SMB FST is compatible with this, but for best performance it should be turned off. To do this, enter the following command in the Terminal, and then turn File Sharing off and back on:

    sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server SigningRequired -bool FALSE


### Samba Server Configuration

In order to properly support IIGS-style file types and resource forks, it is strongly recommended to enable the `vfs_fruit` module. This can be done by adding setting like the following to the `smb.conf` file (in the `[global]` section or the section for a specific share):

    vfs objects = catia fruit streams_xattr
    fruit:encoding = native

If you are configuring Samba via a management interface (e.g. on a NAS) rather than by editing `smb.conf` directly, use of the `vfs_fruit` module may be controlled by a Mac compatibility setting.

In order for Samba servers to be listed in the SMB control panel, the server system must be running an mDNS responder such as Avahi. This is installed by default in many Linux distributions, but on some systems you may need to install it yourself. (You can still connect to Samba servers by entering their address in the SMB control panel, even if they do not have an mDNS responder.)


### Solaris or illumos Server Configuration

The Solaris or illumos SMB servers should typically work without requiring configuration changes.

By default, Solaris or illumos SMB servers do not advertise themselves using mDNS-SD, so they will not be listed in the SMB control panel. You can still connect to them by entering their addresses, but if you want them to show up in the list, you can follow the steps described [here][2].

[2]: https://www.tumfatig.net/2023/smb-shares-using-omnios-zones-and-zfs/#announce-the-smb-service


### General Server Requirements

In order to work with the SMB FST, a server must meet the following requirements. The default configurations of Windows, macOS, Samba, Solaris, and illumos servers meet most of these requirements (except as mentioned above), but if you have customized your server configuration, you should check that it follows them.

* The SMB FST supports SMB protocol versions 2.0.2 through 3.0.2. The server must support at least one of these versions.

* The server must support NTLMv2 authentication.

* The server must not require encryption of SMB messages.

* The server may require message signing, but this substantially reduces performance, so you may wish to disable it.

* The SMB FST represents file types and resource forks on the server using alternate data streams (ADSs), in a manner compatible with macOS. In order to fully support these features, the server must support ADSs. The SMB FST can connect to servers without this support, but some operations will not work on them.

* The SMB FST can use an Apple-specific protocol extension to improve the speed of listing directory contents, so this should be enabled if it is available on the server.

* The SMB control panel detects servers on the local network using multicast DNS Service Discovery (mDNS-SD), so servers must support this in order to be detected. You can still connect to servers that are not detected by manually entering their address.
