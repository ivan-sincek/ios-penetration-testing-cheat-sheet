# iOS Penetration Testing Cheat Sheet

This is more of a checklist for myself. May contain useful tips and tricks. **Still need to add a lot of things.**

Everything was tested on Kali Linux v2024.2 (64-bit) and iPhone 7 with iOS v13.4.1 and unc0ver jailbreak v8.0.2.

For help with any of the tools type `<tool_name> [-h | -hh | --help]` or `man <tool_name>`.

If you didn't already, read [OWAS MASTG](https://mas.owasp.org/MASTG/) \([GitHub](https://github.com/OWASP/owasp-mastg)\) and [OWASP MASVS](https://mas.owasp.org/MASVS/) \([GitHub](https://github.com/OWASP/owasp-masvs)\). You can download OWASP MASTG checklist from [here](https://github.com/OWASP/owasp-mastg/releases).

I also recommend reading [Hacking iOS Applications](https://web.securityinnovation.com/hubfs/iOS%20Hacking%20Guide.pdf) and [HackTricks - iOS Pentesting](https://book.hacktricks.xyz/mobile-apps-pentesting/ios-pentesting).

__In most cases, to be eligible for a bug bounty reward, you need to exploit a vulnerability with non-root priviledges, possibly building your own "malicious" app.__

Websites that you should use while writing the report:

* [cwe.mitre.org/data](https://cwe.mitre.org/data)
* [owasp.org/projects](https://owasp.org/projects)
* [owasp.org/www-project-mobile-top-10](https://owasp.org/www-project-mobile-top-10)
* [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/Glossary.html)
* [first.org/cvss/calculator/4.0](https://www.first.org/cvss/calculator/4.0)
* [bugcrowd.com/vulnerability-rating-taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
* [nvd.nist.gov/ncp/repository](https://nvd.nist.gov/ncp/repository)
* [attack.mitre.org](https://attack.mitre.org)

My other cheat sheets:

* [Android Testing Cheat Sheet](https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet)
* [Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/penetration-testing-cheat-sheet)
* [WiFi Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet)

Future plans:

* test widgets, push notifications, app extensions, and Firebase,
* deeplink hijacking,
* WebView attacks,
* disassemble, reverse engineer, and resign an IPA,
* future downgrades using SHSH BLOBS.

## Table of Contents

**-1. [Jailbreaking](#-1-jailbreaking)**

* [Dopamine](#dopamine)
* [unc0ver](#unc0ver)
* [3uTools](#3utools)

**0. [Install Tools](#0-install-tools)**

* [Cydia Sources and Tools](#cydia-sources-and-tools)
* [SSL Kill Switch 2](#ssl-kill-switch-2)
* [Kali Linux Tools](#kali-linux-tools)
* [Mobile Security Framework (MobSF)](#mobile-security-framework-mobsf)
* [Install Web Proxy Certificates](#install-web-proxy-certificates)

**1. [Basics](#1-basics)**

* [Install/Uninstall an IPA](#installuninstall-an-ipa)
* [SSH to Your iOS Device](#ssh-to-your-ios-device)
* [Download/Upload Files and Directories](#downloadupload-files-and-directories)

**2. [Inspect an IPA](#2-inspect-an-ipa)**

* [Pull a Decrypted IPA](#pull-a-decrypted-ipa)
* [Binary](#binary)
* [Info.plist](#infoplist)
* [AnyTrans](#anytrans)

**3. [Search for Files and Directories](#3-search-for-files-and-directories)**

* [NSUserDefaults](#nsuserdefaults)
* [Cache.db](#cachedb)

**4. [Inspect Files](#4-inspect-files)**

* [Single File](#single-file)
* [Multiple Files](#multiple-files)
* [File Scraper](#file-scraper)
* [SQLite 3](#sqlite-3)
* [Property Lister](#property-lister)
* [Nuclei](#nuclei)
* [Backups](#backups)

**5. [Deeplinks](#5-deeplinks)**

**6. [Frida](#6-frida)**

* [Frida Scripts](#frida-scripts)

**7. [Objection](#7-objection)**

* [Bypasses](#bypasses)

**8. [Repackage an IPA](#8-repackage-an-ipa)**

**9. [Miscellaneous](#9-miscellaneous)**

* [Monitor the System Log](#monitor-the-system-log)
* [Monitor File Changes](#monitor-file-changes)
* [Dump the Pasteboard](#dump-the-pasteboard)
* [Get the Provisioning Profile](#get-the-provisioning-profile)

**10. [Tips and Security Best Practices](#10-tips-and-security-best-practices)**

**11. [Useful Websites and Tools](#11-useful-websites-and-tools)**

## -1. Jailbreaking

**Jailbreaking an iOS device will void its warranty. I have no [liability](https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/LICENSE) over your actions.**

### Dopamine

Jailbreak your iOS device using [Sideloadly](https://sideloadly.io), [TrollStore](https://github.com/34306/TrollStar), and [Dopamine](https://ellekit.space/dopamine) jailbreak.

Make sure you are logged in to iTunes for Sideloadly to work.

Follow [cfw iOS Guide](https://ios.cfw.guide/installing-trollstore-trollstar) to install TrollStore on your iOS device.

Once you have sideloaded the IPA, enable the now-visible developer mode in `Settings -> Privacy & Security -> Developer Mode`.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/dopamine_official_website.png" alt="unc0ver Official Website" height="600em"></p>

<p align="center">Figure 1 - Dopamine Official Website</p>

Deep linking didn't work for me, so I had to manually install the IPA from a URL in TrollStore.

### unc0ver

Jailbreak your iOS device using [AltStore](https://altstore.io) and [unc0ver](https://unc0ver.dev) jailbreak.

Follow [AltStore Docs](https://faq.altstore.io) to install AltStore on your PC.

\[Optional\] Fix the sideloading [issue](https://github.com/altstoreio/AltStore/issues/156#issuecomment-717133644) when installing AltStore on your iOS device. You can also use AltStore to install many other cool apps.

On your iOS device, open Safari, go to [unc0ver.dev](https://unc0ver.dev), and press on `Open in AltStore`. Make sure your antivirus is disabled because it will flag unc0ver IPA as a malware and delete it from your PC.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/unc0ver_official_website.png" alt="unc0ver Official Website" height="600em"></p>

<p align="center">Figure 2 - unc0ver Official Website</p>

Open unc0ver, open the settings in the top-left corner, select it as in the image below, and run the jailbreak.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/unc0ver_jailbreaking.png" alt="unc0ver Jailbreak" height="600em"></p>

<p align="center">Figure 3 - unc0ver Jailbreak</p>

### 3uTools

If you don't mind sending logs to China, you can also try jailbreaking using [3uTools](https://www.3u.com), it is very easy to use.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/3utools_jailbreaking.jpg" alt="Jailbreaking using 3uTools"></p>

<p align="center">Figure 4 - Jailbreaking using 3uTools</p>

## 0. Install Tools

### Cydia Sources and Tools

Add the following sources to Cydia:

* [build.frida.re](https://build.frida.re)
* [cydia.akemi.ai](https://cydia.akemi.ai)
* [repo.co.kr](https://repo.co.kr)
* [havoc.app](https://havoc.app)
* [julioverne.github.io](https://julioverne.github.io)

Install required tools on your iOS device using Cydia:

* A-Bypass
* AppSync Unified
* Cycript
* Cydia Substrate
* Debian Packager
* Frida \([fix for v16+ installation issue](https://github.com/frida/frida/issues/2355#issuecomment-1386757290))
* nano
* PreferenceLoader
* ReProvision Reborn
* SSL Kill Switch 2 (iOS 13)
* SQLite 3.x
* wget
* zip

Over time, some apps might start throwing errors due to the new updates, if reinstalling them using Cydian does not solve the issues, then try to uninstall them completely and install them again.

### SSL Kill Switch 2

The following project is the original SSL Kill Switch 2 project which is discontinued and not supported on devices with iOS v13 and grater. To download the most up-to-date project, check the [julioverne.github.io](https://julioverne.github.io) repository in Cydia.

[SSH](#ssh-to-your-ios-device) to your iOS device, then, download and install [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2/releases):

```fundamental
wget https://github.com/nabla-c0d3/ssl-kill-switch2/releases/download/0.14/com.nablac0d3.sslkillswitch2_0.14.deb

dpkg -i com.nablac0d3.sslkillswitch2_0.14.deb

killall -HUP SpringBoard
```

Uninstall SSL Kill Switch 2:

```fundamental
dpkg -r --force-all com.nablac0d3.sslkillswitch2
```

### Kali Linux Tools

Install required tools on your Kali Linux:

```fundamental
apt-get -y install docker.io

systemctl start docker

apt-get -y install ideviceinstaller libimobiledevice-utils libplist-utils nuclei radare2 sqlite3 sqlitebrowser xmlstarlet

pip3 install frida-tools objection property-lister file-scraper
```

More information about my tools can be found at [ivan-sincek/property-lister](https://github.com/ivan-sincek/property-lister) and [ivan-sincek/file-scraper](https://github.com/ivan-sincek/file-scraper).

Make sure that Frida and Objection are always up to date:

```fundamental
pip3 install --upgrade frida-tools objection
```

### Mobile Security Framework (MobSF)

Install:

```fundamental
docker pull opensecurity/mobile-security-framework-mobsf
```

Run:

```fundamental
docker run -it --rm --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

Navigate to `http://localhost:8000` using your preferred web browser. Username and password are `mobsf:mobsf`.

Uninstall:

```fundamental
docker image rm opensecurity/mobile-security-framework-mobsf
```

## Install Web Proxy Certificates

Open [Burp Suite](https://portswigger.net/burp/communitydownload), navigate to `Proxy --> Proxy Settings` and save the certificate, e.g., as `burp_suite_root_ca.der`.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/exporting_burp_suite_proxy_certificate.png" alt="Exporting Burp Suite Proxy Certificate"></p>

<p align="center">Figure 5 - Exporting Burp Suite Proxy Certificate</p>

Open [ZAP](https://www.zaproxy.org), navigate to `Tools --> Options --> Network --> Server Certificates`, and save the certificate, e.g., as `zap_root_ca.cer`.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/exporting_zap_certificate.png" alt="Exporting ZAP Certificate"></p>

<p align="center">Figure 6 - Exporting ZAP Certificate</p>

On your Kali Linux, start a local web server, and put the certificates in the web root directory (e.g., `somedir`):

```fundamental
mkdir somedir

python3 -m http.server 9000 --directory somedir
```

On your iOS device, download the certificates with Safari.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/installing_cert_profile.png" alt="Installing a Certificate Profile" height="600em"></p>

<p align="center">Figure 7 - Installing a Certificate Profile</p>

## 1. Basics

### Install/Uninstall an IPA

Install an IPA:

```fundamental
ideviceinstaller -i someapp.ipa
```

Uninstall an IPA:

```fundamental
ideviceinstaller -U com.someapp.dev
```

---

Install an IPA using [Sideloadly](https://sideloadly.io) desktop app.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/sideloadly_sideloading.jpg" alt="Sideloading an IPA using Sideloadly"></p>

<p align="center">Figure 8 - Sideloading an IPA using Sideloadly</p>

---

On your Kali Linux, start a local web server, and put an IPA in the web root directory (e.g., `somedir`):

```fundamental
mkdir somedir

python3 -m http.server 9000 --directory somedir
```

On your iOS device, download the IPA, long press on it, choose "Share", and install it using [ReProvision Reborn](https://havoc.app/package/rpr) iOS app. Jailbreak is required.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/reprovision_reborn_sideloading.jpg" alt="Sideloading an IPA using ReProvision Reborn" height="600em"></p>

<p align="center">Figure 9 - Sideloading an IPA using ReProvision Reborn</p>

If you have an Apple developer membership, you can code sign your apps for up to 1 year; otherwise, you will need to re-sing them every 7 days.

---

If you don't mind sending logs to China. Install an IPA using [3uTools](https://www.3u.com) desktop app. Jailbreak is required.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/3utools_sideloading.jpg" alt="Sideloading an IPA using 3uTools"></p>

<p align="center">Figure 10 - Sideloading an IPA using 3uTools</p>

### SSH to Your iOS Device

```fundamental
ssh root@192.168.1.10
```

Default password is `alpine`.

### Download/Upload Files and Directories

Tilde `~` is short for the root directory.

Download a file or directory from your iOS device:

```fundamental
scp root@192.168.1.10:~/somefile.txt ./

scp -r root@192.168.1.10:~/somedir ./
```

Upload a file or directory to your iOS device:

```fundamental
scp somefile.txt root@192.168.1.10:~/

scp -r somedir root@192.168.1.10:~/
```

Use `nano` to edit files directly on your iOS device.

## 2. Inspect an IPA

### Pull a Decrypted IPA

Pull a decrypted IPA from your iOS device:

```bash
git clone https://github.com/AloneMonkey/frida-ios-dump && cd frida-ios-dump && pip3 install -r requirements.txt

python3 dump.py -o decrypted.ipa -P alpine -p 22 -H 192.168.1.10 com.someapp.dev
```

If you want to pull an encrypted IPA from your iOS device, see section [9. Repackage an IPA](#8-repackage-an-ipa) and [AnyTrans](#anytrans).

To unpack, e.g., `someapp.ipa` or `decrypted.ipa` (preferred), run:

```fundamental
unzip decrypted.ipa
```

You should now see the unpacked `Payload` directory.

### Binary

Navigate to `Payload/someapp.app/` directory. There, you will find a binary which have the same name and no file type (i.e., `someapp`).

Search the binary for specific keywords:

```bash
rabin2 -zzzqq someapp | grep -Pi 'keyword'

rabin2 -zzzqq someapp | grep -Pi 'hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView'
```

WebViews can sometimes be very subtle, e.g., they could be hidden as a link to terms of agreement, privacy policy, about the software, referral, etc.

Search the binary for endpoints, deeplinks, sensitive data, comments, etc. For more examples, see section [4. Inspect Files](#4-inspect-files).

Search the binary for weak hash algorithms, insecure random functions, insecure memory allocation functions, etc. For the best results, use [MobSF](#mobile-security-framework-mobsf).

---

Download the latest [AppInfoScanner](https://github.com/kelvinBen/AppInfoScanner/releases), install the requirements, and then extract and resolve endpoints from the binary, or directly from the IPA:

```fundamental
pip3 install -r requirements.txt

python3 app.py ios -i someapp
```

### Info.plist

Navigate to `Payload/someapp.app/` directory. There, you will find a property list file with the name `Info.plist`.

Extract URL schemes from the property list file:

```bash
xmlstarlet sel -t -v 'plist/dict/array/dict[key = "CFBundleURLSchemes"]/array/string' -nl Info.plist 2>/dev/null | sort -uf | tee url_schemes.txt
```

Search the property list file for endpoints, sensitive data \[in Base64 encoding\], etc. For more examples, see section [4. Inspect Files](#4-inspect-files).

### AnyTrans

Export an IPA using [AnyTrans](https://www.imobie.com/anytrans) desktop app. Excellent for iOS backups too.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/anytrans_download.png" alt="Download an IPA using AnyTrans"></p>

<p align="center">Figure 11 - Download an IPA using AnyTrans</p>

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/anytrans_export.png" alt="Export an IPA using AnyTrans"></p>

<p align="center">Figure 12 - Export an IPA using AnyTrans</p>

## 3. Search for Files and Directories

Search for files and directories from the root directory:

```bash
find / -iname '*keyword*'
```

Search for files and directories in the app specific directories (run `env` in [Objection](#7-objection)):

```bash
cd /private/var/containers/Bundle/Application/XXX...XXX/

cd /var/mobile/Containers/Data/Application/YYY...YYY/
```

If you want to download a whole directory from your iOS device, see section [Download/Upload Files and Directories](#downloadupload-files-and-directories).

I preffer downloading the app specific directories, and then doing the [file inspection](#4-inspect-files) on my Kali Linux.

Search for files and directories from the current directory:

```bash
find . -iname '*keyword*'

for keyword in 'access' 'account' 'admin' 'card' 'cer' 'conf' 'cred' 'customer' 'email' 'history' 'info' 'json' 'jwt' 'key' 'kyc' 'log' 'otp' 'pass' 'pem' 'pin' 'plist' 'priv' 'refresh' 'salt' 'secret' 'seed' 'setting' 'sign' 'sql' 'token' 'transaction' 'transfer' 'tar' 'txt' 'user' 'zip' 'xml'; do find . -iname "*${keyword}*"; done
```

### NSUserDefaults

Search for files and directories in [NSUserDefaults](https://developer.apple.com/documentation/foundation/nsuserdefaults) insecure storage directory:

```bash
cd /var/mobile/Containers/Data/Application/YYY...YYY/Library/Preferences/
```

Search for sensitive data in property list files inside NSUserDefaults insecure storage directory:

```fundamental
scp root@192.168.1.10:/var/mobile/Containers/Data/Application/YYY...YYY/Library/Preferences/com.someapp.dev.plist ./

plistutil -f xml -i com.someapp.dev.plist
```

### Cache.db

By default, NSURLSession class stores data such as HTTP requests and responses in Cache.db unencrypted database file.

Search for sensitive data in property list files inside Cache.db unencrypted database file:

```fundamental
scp root@192.168.1.10:/var/mobile/Containers/Data/Application/YYY...YYY/Library/Caches/com.someapp.dev/Cache.db ./

property-lister -db Cache.db -o plists
```

Cache.db is unencrypted and backed up by default, and as such, should not contain any sensitive data after user logs out - it should be cleared by calling [removeAllCachedResponses\(\)](https://developer.apple.com/documentation/foundation/urlcache/1417802-removeallcachedresponses).

## 4. Inspect Files

Inspect memory dumps, binaries, files inside [an unpacked IPA](#pull-a-decrypted-ipa), files inside the app specific directories, or any other files.

After you finish testing \[and logout\], don't forget to [download](#downloadupload-files-and-directories) the app specific directories and inspect all the files inside. Inspect what is new and what still persists after the logout.

**Don't forget to extract Base64 strings from property list files as you might find sensitive data.**

There will be some false positive results since the regular expressions are not perfect. I prefer to use `rabin2` over `strings` because it can read Unicode characters.

On your iOS device, try to modify app's files to test the filesystem checksum validation, i.e., to test the file integrity validation.

### Single File

Search for hardcoded sensitive data:

```bash
rabin2 -zzzqq somefile | grep -Pi '[^\w\d\n]+(?:basic|bearer)\ .+'

rabin2 -zzzqq somefile | grep -Pi '(?:access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)[\w\d]*(?:\"\ *\:|\ *\=).+'

rabin2 -zzzqq somefile | grep -Pi '[^\w\d\n]+(?:bug|comment|fix|issue|note|problem|to(?:\_|\ |)do|work)[^\w\d\n]+.+'
```

Extract URLs, deeplinks, IPs, etc.:

```bash
rabin2 -zzzqq somefile | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | sort -uf | tee urls.txt

rabin2 -zzzqq somefile | grep -Po '(?:\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
rabin2 -zzzqq somefile | sort -uf > strings.txt

grep -Po '(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}\=|[a-zA-Z0-9\+\/]{2}\=\=)' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -PI '[\s\S]+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### Multiple Files

Search for hardcoded sensitive data:

```bash
IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '[^\w\d\n]+(?:basic|bearer)\ .+'; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '(?:access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)[\w\d]*(?:\"\ *\:|\ *\=).+'; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '[^\w\d\n]+(?:bug|comment|fix|issue|note|problem|to(?:\_|\ |)do|work)[^\w\d\n]+.+'; done
```

Extract URLs, deeplinks, IPs, etc.:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | grep -Piv '\.(css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)' | sort -uf | tee urls.txt

IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | grep -Po '(?:\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | sort -uf > strings.txt

grep -Po '(?:[a-zA-Z0-9\+\/]{4})*(?:[a-zA-Z0-9\+\/]{4}|[a-zA-Z0-9\+\/]{3}\=|[a-zA-Z0-9\+\/]{2}\=\=)' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -PI '[\s\S]+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### File Scraper

Automate all of the above file inspection (and more) with a single tool, also using multithreading.

```bash
apt-get -y install radare2

pip3 install file-scraper
```
  
```fundamental
file-scraper -dir Payload -o results.html -e default
```

More about my other project at [ivan-sincek/file-scraper](https://github.com/ivan-sincek/file-scraper).

### SQLite 3

Use [SCP](#downloadupload-files-and-directories) to download database files, and then open them using [DB Browser for SQLite](https://sqlitebrowser.org).

To inspect the content, navigate to `Browse Data` tab, expand `Table` dropdown menu, and select the desired table.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/sqlite.png" alt="SQLite"></p>

<p align="center">Figure 13 - DB Browser for SQLite</p>

To inspect/edit database files on your iOS device, use [SQLite 3](#cydia-sources-and-tools); [SSH](#ssh-to-your-ios-device) to your iOS device and run the following commands:

```sql
sqlite3 somefile

.dump

.tables

SELECT * FROM sometable;

.quit
```

[Property Lister](#property-lister) will dump all databases in plain-text automatically.

### Property Lister

Unpack, e.g., `someapp.ipa` or [decrypted.ipa](#pull-a-decrypted-ipa) (preferred).

Dump all the databases, and extract and convert all the property list files inside an IPA:

```fundamental
property-lister -db Payload -o results_db

property-lister -pl Payload -o results_pl
```

Repeat the same for [the app specific directories](#3-search-for-files-and-directories).

More about my other project at [ivan-sincek/property-lister](https://github.com/ivan-sincek/property-lister).

### Nuclei

Download mobile Nuclei templates:

```fundamental
git clone https://github.com/optiv/mobile-nuclei-templates ~/mobile-nuclei-templates
```

Unpack, e.g., `someapp.ipa` or [decrypted.ipa](#pull-a-decrypted-ipa) (preferred).

Search for hardcoded sensitive data:

```bash
echo Payload | nuclei -t ~/mobile-nuclei-templates/Keys/ -o nuclei_keys_results.txt

cat nuclei_keys_results.txt | grep -Po '(?<=\]\ ).+' | sort -uf > nuclei_keys_results_sorted.txt
```

### Backups

Get your iOS device UDID:

```fundamental
idevice_id -l
```

Create a backup:

```bash
idevicebackup2 backup --full -u $(idevice_id -l) ./backup
```

App should not backup any sensitive data.

Restore from a backup:

```bash
idevicebackup2 restore -u $(idevice_id -l) ./backup
```

---

Browse backups using [iExplorer](https://macroplant.com/iexplorer) (demo) for Windows OS. There are many other iOS backup tools, but they cannot browse app specific directories.

iExplorer's default directory for storing iOS backups:

```fundamental
C:\Users\%USERNAME%\AppData\Roaming\Apple Computer\MobileSync\Backup\
```

You can place your backups in either this directory or change it in settings.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/iexplorer.png" alt="iExplorer"></p>

<p align="center">Figure 14 - iExplorer</p>

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/iexplorer_browse.png" alt="Browse a backup using iExplorer"></p>

<p align="center">Figure 15 - Browse a backup using iExplorer</p>

## 5. Deeplinks

Test [/.well-known/apple-app-site-association](https://developer.apple.com/documentation/xcode/supporting-associated-domains) using [branch.io/resources/aasa-validator](https://branch.io/resources/aasa-validator).

Sometimes, deeplinks can bypass authentication, including biometrics.

Create an HTML template to manually test deeplinks:

```bash
mkdir ios_deeplinks

# multiple URL schemes

for scheme in $(cat url_schemes.txt); do for url in $(cat urls.txt | grep -Poi "${scheme}\:\/\/.+"); do if [[ ! -z $url ]]; then echo -n "<a href='${url}'>${url}</a>\n<br><br>\n" | tee -a "ios_deeplinks/${scheme}_deeplinks.html"; fi; done; done

# single URL scheme

scheme="somescheme"; for string in $(cat urls.txt | grep -Poi "${scheme}\:\/\/.+"); do echo -n "<a href='${string}'>${string}</a>\n<br><br>\n"; done | tee -a "ios_deeplinks/${scheme}_deeplinks.html"

python3 -m http.server 9000 --directory ios_deeplinks
```

For `url_schemes.txt` see section [Info.plist](#infoplist), and for `urls.txt` see section [4. Inspect Files](#4-inspect-files).

---

Fuzz deeplinks using [ios-deeplink-fuzzing](https://codeshare.frida.re/@ivan-sincek/ios-deeplink-fuzzing) script with [Frida](#6-frida):

```fundamental
frida -U -no-pause -l ios-deeplink-fuzzing.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/ios-deeplink-fuzzing -f com.someapp.dev
```

Check the source code for more instructions. You can also paste the whole source code directly into Frida and call the methods as you prefer.

## 6. Frida

Useful resources:

* [frida.re](https://frida.re/docs/home)
* [learnfrida.info](https://learnfrida.info)
* [codeshare.frida.re](https://codeshare.frida.re)
* [dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida)
* [interference-security/frida-scripts](https://github.com/interference-security/frida-scripts)
* [m0bilesecurity/Frida-Mobile-Scripts](https://github.com/m0bilesecurity/Frida-Mobile-Scripts)

List processes:

```bash
frida-ps -Uai

frida-ps -Uai | grep -i 'keyword'
```

Get PID for a specified keyword:

```bash
frida-ps -Uai | grep -i 'keyword' | cut -d ' ' -f 1
```

Discover internal methods/calls:

```bash
frida-discover -U -f com.someapp.dev | tee frida_discover.txt
```

Trace internal methods/calls:

```bash
frida-trace -U -p 1337

frida-trace -U -p 1337 -i 'recv*' -i 'send*'
```

### Frida Scripts

Bypass biometrics using [ios-touch-id-bypass](https://codeshare.frida.re/@ivan-sincek/ios-touch-id-bypass) script:

```fundamental
frida -U -no-pause -l ios-touch-id-bypass.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/ios-touch-id-bypass -f com.someapp.dev
```

On the touch ID prompt, press `Cancel`.

I prefer to use the built-in method in [Objection](#bypasses).

---

Hook all classes and methods using [ios-hook-classes-methods](https://codeshare.frida.re/@ivan-sincek/ios-hook-classes-methods) script:

```fundamental
frida -U -no-pause -l ios-hook-classes-methods.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/ios-hook-classes-methods -f com.someapp.dev
```

## 7. Objection

Useful resources:

* [sensepost/objection](https://github.com/sensepost/objection)

Run:

```fundamental
objection -g com.someapp.dev explore
```

Run a [Frida](#6-frida) script in Objection:

```fundamental
import somescript.js

objection -g com.someapp.dev explore --startup-script somescript.js
```

Get information:

```fundamental
ios info binary

ios plist cat Info.plist
```

Get environment variables:

```fundamental
env
```

Get HTTP cookies:

```fundamental
ios cookies get
```

Dump Keychain, NSURLCredentialStorage, and NSUserDefaults:

```fundamental
ios keychain dump

ios nsurlcredentialstorage dump

ios nsuserdefaults get
```

Sensitive data such as app's PIN, password, etc., should not be stored as a plain-text in the keychain; instead, they should be hashed as an additional level of protection.

Dump app's memory to a file:

```fundamental
memory dump all mem.dmp
```

Dump app's memory after, e.g., 10 minutes of inactivity, then, check if sensitive data is still in the memory, see section [4. Inspect Files](#4-inspect-files).

**In case Objection detaches from the app, use the process ID to attach it back without restarting the app.**

Search app's memory directly:

```bash
memory search 'somestring' --string
```

List classes and methods:

```bash
ios hooking list classes
ios hooking search classes 'keyword'

ios hooking list class_methods 'someclass'
ios hooking search methods 'keyword'
```

Hook on a class or method:

```bash
ios hooking watch class 'someclass'

ios hooking watch method '-[someclass somemethod]' --dump-args --dump-backtrace --dump-return
```

Change the method's return value:

```bash
ios hooking set return_value '-[someclass somemethod]' false
```

Monitor crypto libraries:

```fundamental
ios monitor crypto
```

Monitor the pasteboard:

```fundamental
ios pasteboard monitor
```

You can also dump the pasteboard using [cycript](#dump-the-pasteboard).

### Bypasses

Bypass a jailbreak detection:

```bash
ios jailbreak disable --quiet

objection -g com.someapp.dev explore --startup-command 'ios jailbreak disable --quiet'
```

Also, on your iOS device, check `A-Bypass` in `Settings` app.

---

Bypass SSL pinning:

```bash
ios sslpinning disable --quiet

objection -g com.someapp.dev explore --startup-command 'ios sslpinning disable --quiet'
```

Also, on your iOS device, check [SSL Kill Switch 2](#ssl-kill-switch-2) in `Settings` app.

---

Bypass biometrics:

```bash
ios ui biometrics_bypass --quiet

objection -g com.someapp.dev explore --startup-command 'ios ui biometrics_bypass --quiet'
```

Also, you can import [Frida](#frida-scripts) script.

## 8. Repackage an IPA

[SSH](#ssh-to-your-ios-device) to your iOS device and run the following commands.

Navigate to the app specific directory:

```bash
cd /private/var/containers/Bundle/Application/XXX...XXX/
```

Repackage the IPA:

```fundamental
mkdir Payload

cp -r someapp.app Payload

zip -r repackaged.ipa Payload

rm -rf Payload
```

On your Kali Linux, download the repackaged IPA:

```fundamental
scp root@192.168.1.10:/private/var/containers/Bundle/Application/XXX...XXX/repackaged.ipa ./
```

If you want to pull a decrypted IPA from your iOS device, see section [Pull a Decrypted IPA](#pull-a-decrypted-ipa).

## 9. Miscellaneous

### Monitor the System Log

On your Kali Linux, run the following command:

```fundamental
idevicesyslog -p 1337
```

Or, get the PID from a keyword:

```fundamental
keyword="keyword"; idevicesyslog -p $(frida-ps -Uai | grep -i "${keyword}" | tr -s '[:blank:]' ' ' | cut -d ' ' -f 1)
```

### Monitor File Changes

[SSH](#ssh-to-your-ios-device) to your iOS device, then, download and run [Filemon](http://www.newosxbook.com):

```bash
wget http://www.newosxbook.com/tools/filemon.tgz && tar zxvf filemon.tgz && chmod +x filemon

./filemon -c -f com.someapp.dev
```

Always look for created or cached files, images/screenshots, etc. Use `nano` to edit files directly on your iOS device.

Sensitive files such as know your customer (KYC) and similar, should not persists in the app specific directories on user's device after the file upload. Sensitive files should not be stored in `/tmp/` directory nor similar system-wide directories.

Images and screenshots path:

```fundamental
cd /var/mobile/Containers/Data/Application/YYY...YYY/Library/SplashBoard/Snapshots/
```

### Dump the Pasteboard

After copying sensitive data, the app should wipe the pasteboard after a short period of time.

[SSH](#ssh-to-your-ios-device) to your iOS device and run the following commands:

```fundamental
cycript -p 1337

[UIPasteboard generalPasteboard].items
```

Press `CTRL + D` to exit.

You can also monitor the pasteboard in [Objection](#7-objection).

### Get the Provisioning Profile

```fundamental
scp root@192.168.1.10:/private/var/containers/Bundle/Application/XXX...XXX/*.app/embedded.mobileprovision ./

openssl smime -inform der -verify -noverify -in embedded.mobileprovision
```

## 10. Tips and Security Best Practices

Bypass any keyboard restriction by copying and pasting data into an input field.

Access tokens should be short lived, and if possible, invalidated on logout.

Don't forget to test widgets, push notifications, app extensions, and Firebase.

Sometimes, deeplinks and widgets can bypass authentication, including biometrics.

Only if explicitly allowed, try flooding 3rd party APIs to cause possible monetary damage to the company, or denial-of-service (DoS) by exhausting the allowed quotas/limits.

---

App should not disclose sensitive data in the predictive text (due to incorrectly defined input field type), app switcher, and push notifications.

App should warn a user when taking a screenshot of sensitive data.

App should warn a user that it is trivial to bypass biometrics authentication if iOS device is jailbroken.

Production app (i.e., build) should not be debuggable.

## 11. Useful Websites and Tools

| URL | Description |
| --- | --- |
| [developer.apple.com/account](https://developer.apple.com/account) | Official iOS documentation, create code signing certificates, etc. |
| [developer.apple.com/apple-pay/sandbox-testing](https://developer.apple.com/apple-pay/sandbox-testing) | Test debit/credit cards for Apple Pay. |
| [streaak/keyhacks](https://github.com/streaak/keyhacks) | Validate various API keys. |
| [zxing.org/w/decode.jspx](https://zxing.org/w/decode.jspx) | Decode QR codes. |
| [youtube.com/user/iDeviceMovies](https://www.youtube.com/user/iDeviceMovies) | Useful videos about jailbreaking, etc. |
| [ipsw.me/product/iPhone](https://ipsw.me/product/iPhone) | Firmwares for Apple devices. |
