# iOS Penetration Testing Cheat Sheet

This is more of a checklist for myself. May contain useful tips and tricks.

Everything was tested on Kali Linux v2022.2 (64-bit) and iPhone 7 with iOS v13.4.1 and unc0ver jailbreak v8.0.2.

Check [3uTools](https://www.3u.com) if you want to jailbreak your mobile device. I have no [liability](https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/LICENSE) over your actions.

For help with any of the tools type `<tool_name> [-h | -hh | --help]` or `man <tool_name>`.

If you didn't already, read the [OWASP MSTG](https://mobile-security.gitbook.io/mobile-security-testing-guide).

Highly recommend reading [Hacking iOS Applications](https://web.securityinnovation.com/hubfs/iOS%20Hacking%20Guide.pdf) and [HackTricks - iOS Pentesting](https://book.hacktricks.xyz/mobile-apps-pentesting/ios-pentesting).

Websites that you should use while writing the report:

* [cwe.mitre.org/data](https://cwe.mitre.org/data)
* [owasp.org/projects](https://owasp.org/projects)
* [owasp.org/www-project-mobile-top-10](https://owasp.org/www-project-mobile-top-10)
* [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/Glossary.html)
* [nvd.nist.gov/vuln-metrics/cvss/v3-calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [nvd.nist.gov/ncp/repository](https://nvd.nist.gov/ncp/repository)
* [attack.mitre.org](https://attack.mitre.org)

My other cheat sheets:

* [Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/penetration-testing-cheat-sheet)
* [WiFi Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet)

Future plans:

* install Burp Proxy and ZAP certificates,
* test widgets, push notifications, app extensions, and Firebase,
* disassemble, reverse engineer, and resign IPA.

## Table of Contents

**0. [Install Tools](#0-install-tools)**

* [Cydia Sources and Tools](#cydia-sources-and-tools)
* [SSL Kill Switch 2](#ssl-kill-switch-2)
* [Kali Linux Tools](#kali-linux-tools)
* [Mobile Security Framework (MobSF)](#mobile-security-framework-mobsf)

**1. [Basics](#1-basics)**

* [Install/Uninstall IPA](#installuninstall-ipa)
* [SSH to Your Mobile Device](#ssh-to-your-mobile-device)
* [Download/Upload Files and Directories](#downloadupload-files-and-directories)

**2. [Inspect IPA](#2-inspect-ipa)**

* [Pull Decrypted IPA](#pull-decrypted-ipa)
* [Binary](#binary)
* [Info.plist](#infoplist)

**3. [Search for Files and Directories](#3-search-for-files-and-directories)**

* [NSUserDefaults](#nsuserdefaults)

**4. [Inspect Files](#4-inspect-files)**

* [Single File](#single-file)
* [Multiple Files](#multiple-files)
* [SQLite](#sqlite)
* [Backup](#backup)

**5. [Deeplinks](#5-deeplinks)**

**6. [Frida](#6-frida)**

* [Frida Scripts](#frida-scripts)

**7. [Objection](#7-objection)**

* [Bypasses](#bypasses)

**8. [Repackaging](#8-repackaging)**

**9. [Other](#9-other)**

* [Monitor System Log](#monitor-system-log)
* [Monitor File Changes](#monitor-file-changes)
* [Dump Pasteboard](#dump-pasteboard)
* [Get Provisioning Profile](#get-provisioning-profile)
* [Tips](#tips)

## 0. Install Tools

### Cydia Sources and Tools

Add the following sources to Cydia:

* [build.frida.re](https://build.frida.re)
* [cydia.akemi.ai](https://cydia.akemi.ai)
* [repo.co.kr](https://repo.co.kr)
* [repo.packix.com](https://repo.packix.com)

Install the required tools on your mobile device:

* A-Bypass
* AppSync Unified
* Cycript
* Cydia Substrate
* Debian Packager
* Frida
* nano
* PreferenceLoader
* ReProvision Reborn
* SQLite 3.x
* wget
* zip

### SSL Kill Switch 2

[SSH](#ssh-to-your-mobile-device) to your mobile device, download and install [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2/releases):

```bash
wget https://github.com/nabla-c0d3/ssl-kill-switch2/releases/download/0.14/com.nablac0d3.sslkillswitch2_0.14.deb

dpkg -i com.nablac0d3.sslkillswitch2_0.14.deb

killall -HUP SpringBoard
```

Uninstall SSL Kill Switch 2:

```fundamental
dpkg -r --force-all com.nablac0d3.sslkillswitch2
```

### Kali Linux Tools

Install the required tools on your Kali Linux:

```fundamental
apt-get -y install ideviceinstaller libimobiledevice-utils libplist-utils radare2 sqlitebrowser xmlstarlet

pip3 install frida-tools objection
```

Make sure that these two tools are always up to date:

```fundamental
pip3 install frida-tools objection --upgrade
```

### Mobile Security Framework (MobSF)

Install and run Docker:

```fundamental
apt-get -y install docker.io

systemctl start docker
```

Pull MobSF:

```fundamental
docker pull opensecurity/mobile-security-framework-mobsf
```

Run MobSF:

```fundamental
docker run -it --rm --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

Navigate to `http://localhost:8000` with your preferred web browser.

Uninstall MobSF:

```fundamental
docker image rm opensecurity/mobile-security-framework-mobsf
```

## 1. Basics

### Install/Uninstall IPA

Install IPA:

```fundamental
ideviceinstaller -i someapp.ipa
```

Uninstall IPA:

```fundamental
ideviceinstaller -U com.someapp.dev
```

### SSH to Your Mobile Device

```fundamental
ssh root@192.168.1.10
```

Default password is `alpine`.

### Download/Upload Files and Directories

Tilde `~` is short for a root directory.

Download a file or directory from your mobile device:

```fundamental
scp root@192.168.1.10:~/somefile.txt ./

scp -r root@192.168.1.10:~/somedir/ ./
```

Upload a file or directory to your mobile device:

```fundamental
scp somefile.txt root@192.168.1.10:~/

scp -r somedir root@192.168.1.10:~/
```

You can use `nano` to edit files directly on your mobile device.

## 2. Inspect IPA

### Pull Decrypted IPA

Pull decrypted IPA from your mobile device:

```bash
git clone https://github.com/AloneMonkey/frida-ios-dump && cd frida-ios-dump && pip3 install -r requirements.txt

python3 dump.py -o decrypted.ipa -P alpine -p 22 -H 192.168.1.10 com.someapp.dev
```

If you want to pull encrypted IPA from your mobile device, see section [8. Repackaging](#8-repackaging).

### Binary

Unpack e.g. `someapp.ipa`, then, navigate to e.g. `/Payload/someapp.app/` directory. There, you will find a binary with the same name and with no file type (i.e. `someapp`).

Search the binary for specific keywords:

```bash
rabin2 -zzzq someapp | grep -Pi 'keyword'

rabin2 -zzzq someapp | grep -Pi 'hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView'
```

Web views can sometimes be really subtle, e.g. the only occurrence could be  hidden as a link to terms of agreement, privacy policy, about the software, etc.

Search the binary for endpoints, deeplinks, sensitive data, comments, etc. For more examples, see section [4. Inspect Files](#4-inspect-files).

Extract and resolve endpoints from the binary:

```bash
git clone https://github.com/kelvinBen/AppInfoScanner && cd AppInfoScanner && pip3 install -r requirements.txt

python3 app.py ios -i someapp
```

Search the binary for weak hash algorithms, insecure random functions, insecure memory allocation functions, etc. For best results, use [MobSF](#mobsf).

### Info.plist

Unpack e.g. `someapp.ipa`, then, navigate to e.g. `/Payload/someapp.app/` directory. There, you will find a property list file with the name `Info.plist`.

Extract URL schemes from the property list file:

```bash
xmlstarlet sel -t -v 'plist/dict/array/dict[key = "CFBundleURLSchemes"]/array/string' -nl Info.plist | sort -uf | tee url_schemes.txt
```

Search the property list file for endpoints, sensitive data, etc. For more examples, see section [4. Inspect Files](#4-inspect-files).

## 3. Search for Files and Directories

Search for files and directories from the global root directory:

```bash
find / -iname '*keyword*'
```

Search for files and directories in application specific directories (run `env` in [Objection](#7-objection)):

```bash
cd /private/var/containers/Bundle/Application/XXX...XXX/

cd /var/mobile/Containers/Data/Application/YYY...YYY/
```

If you want to pull a whole directory from your mobile device, see section [Download/Upload Files and Directories](#downloadupload-files-and-directories).

Search for files and directories from the current directory:

```bash
find . -iname '*keyword*'

for keyword in 'account' 'admin' 'card' 'cer' 'conf' 'cred' 'customer' 'email' 'history' 'info' 'json' 'jwt' 'key' 'kyc' 'log' 'otp' 'pass' 'pem' 'pin' 'plist' 'priv' 'secret' 'setting' 'sign' 'sql' 'token' 'transaction' 'transfer' 'tar' 'txt' 'user' 'zip' 'xml'; do find . -iname "*${keyword}*"; done
```

### NSUserDefaults

Search for files and directories in `NSUserDefaults` insecure storage directory:

```bash
cd /var/mobile/Containers/Data/Application/YYY...YYY/Library/Preferences/
```

Search for sensitive data in property list files inside `NSUserDefaults` insecure storage directory:

```fundamental
scp root@192.168.1.10:/var/mobile/Containers/Data/Application/YYY...YYY/Library/Preferences/com.someapp.dev.plist ./

plistutil -f xml -i com.someapp.dev.plist
```

## 4. Inspect Files

Inspect memory dump, binary, or any other files.

There will be some false positive results since the regular expressions are not that perfect.

I prefer to download whole directories with [SCP](#downloadupload-files-and-directories), and then inspect all the files offline. I also prefer to use `rabin2` over `strings`.

On your iOS device, try to modify some files to test filesystem checksum validation, i.e. to test file integrity check.

### Single File

Extract hardcoded sensitive data:

```bash
rabin2 -zzzq somefile | grep -Pi '(basic|bearer)\ '

rabin2 -zzzq somefile | grep -Pi '(account|admin|card|cred|email|id|jwt|key|login|otp|pass|pin|priv|secret|sign|token|transaction|transfer|user)\w*(\"\ *\:|\ *\=)'

rabin2 -zzzq somefile | grep -Pi '(to\ do|todo|\/\/|\/\*|\*\/)'
```

Extract URLs, deeplinks, IPs, etc.:

```bash
rabin2 -zzzq somefile | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | grep -Piv '\.(css|gif|jpeg|jpg|otf|png|svg|ttf|woff|woff2)' | sort -uf | tee urls.txt

rabin2 -zzzq somefile | grep -Po '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
rabin2 -zzzq somefile | grep -Po '(?<=\ ).+' | sort -uf > strings.txt

grep -Po '(?:([a-zA-Z0-9\+\/]){4})*(?1)(?:(?1)\=\=|(?1){2}\=|(?1){3})' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -I '.+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### Multiple Files

Extract hardcoded sensitive data:

```bash
IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzq "$file" 2>/dev/null | grep -Pi '(basic|bearer)\ '; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzq "$file" 2>/dev/null | grep -Pi '(account|admin|card|cred|email|id|jwt|key|login|otp|pass|pin|priv|secret|sign|token|transaction|transfer|user)\w*(\"\ *\:|\ *\=)'; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzq "$file" 2>/dev/null | grep -Pi '(to\ do|todo|\/\/|\/\*|\*\/)'; done
```

Extract URLs, deeplinks, IPs, etc.:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzq "$file" 2>/dev/null; done | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | grep -Piv '\.(css|gif|jpeg|jpg|otf|png|svg|ttf|woff|woff2)' | sort -uf | tee urls.txt

IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzq "$file" 2>/dev/null; done | grep -Po '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzq "$file" 2>/dev/null; done | grep -Po '(?<=\ ).+' | sort -uf > strings.txt

grep -Po '(?:([a-zA-Z0-9\+\/]){4})*(?1)(?:(?1)\=\=|(?1){2}\=|(?1){3})' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -I '.+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### SQLite

Use [SCP](#downloadupload-files-and-directories) to download database files. Once downloaded, open them with [DB Browser for SQLite](https://sqlitebrowser.org).

To inspect the content, navigate to `Browse Data` tab, expand `Table` dropdown menu, and select the desired table.

<p align="center"><img src="https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/img/sqlite.png" alt="SQLite"></p>

<p align="center">Figure 1 - DB Browser for SQLite</p>

To manually inspect and/or edit database files, [SSH](#ssh-to-your-mobile-device) to your mobile device and run the following commands:

```sql
sqlite3 somefile

.dump

.tables

SELECT * FROM sometable;

.quit
```

### Backup

Get your iOS device UDID:

```fundamental
idevice_id -l
```

Create a backup:

```fundamental
idevicebackup2 backup --full --source someudid --udid someudid ./
```

## 5. Deeplinks

Create an HTML template to manually test deeplinks:

```bash
scheme="somescheme"; for string in $(cat urls.txt | grep -Poi "${scheme}\:\/\/.+"); do echo -n "<a href='${string}'>${string}</a>\n<br><br>\n"; done | tee "${scheme}_deeplinks.html"

python3 -m http.server 9000 --directory somedir
```

Fuzz deeplinks with [ios-url-scheme-fuzzing](https://codeshare.frida.re/@ivan-sincek/ios-url-scheme-fuzzing) script using [Frida](#6-frida):

```bash
frida -U --no-pause -l ios-url-scheme-fuzzing.js -f com.someapp.dev

frida -U --no-pause --codeshare ivan-sincek/ios-url-scheme-fuzzing -f com.someapp.dev
```

Check the source code for more instructions. You can also paste the whole source code directly into Frida and call the methods as you desire.

Sometimes, deeplinks can be used to bypass biometrics.

## 6. Frida

Useful resources:

* [frida.re](https://frida.re/docs/home)
* [learnfrida.info](https://learnfrida.info)
* [codeshare.frida.re](https://codeshare.frida.re)
* [github.com/dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida)
* [github.com/interference-security/frida-scripts](https://github.com/interference-security/frida-scripts)
* [github.com/m0bilesecurity/Frida-Mobile-Scripts](https://github.com/m0bilesecurity/Frida-Mobile-Scripts)

List all processes:

```bash
frida-ps -Uai

frida-ps -Uai | grep -i 'keyword'
```

Get only PID for a specified keyword:

```bash
frida-ps -Uai | grep -i 'keyword' | tr -s '[:blank:]' ' ' | cut -d ' ' -f 1
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

Bypass biometrics with [ios-touch-id-bypass](https://codeshare.frida.re/@ivan-sincek/ios-touch-id-bypass) script:

```fundamental
frida -U --no-pause -l ios-touch-id-bypass.js -f com.someapp.dev

frida -U --no-pause --codeshare ivan-sincek/ios-touch-id-bypass -f com.someapp.dev
```

On touch ID prompt, press `Cancel`.

I prefer to use the built-in method in [Objection](#bypasses).

---

Hook all classes and methods with [ios-hook-classes-methods](https://codeshare.frida.re/@ivan-sincek/ios-hook-classes-methods) script:

```fundamental
frida -U --no-pause -l ios-hook-classes-methods.js -f com.someapp.dev

frida -U --no-pause --codeshare ivan-sincek/ios-hook-classes-methods -f com.someapp.dev
```

## 7. Objection

Useful resources:

* [github.com/sensepost/objection](https://github.com/sensepost/objection)

Run:

```fundamental
objection -g com.someapp.dev explore
```

Run [Frida](#6-frida) script in Objection:

```fundamental
import somescript.js

objection -g com.someapp.dev explore --startup-script 'somescript.js'
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

Dump Keychain, `NSURLCredentialStorage`, and `NSUserDefaults`:

```fundamental
ios keychain dump

ios nsurlcredentialstorage dump

ios nsuserdefaults get
```

Secrets such as application's PIN or password should not be stored as plain text in the keychain; instead, they should be hashed as an additional level of protection.

Dump memory to a file:

```fundamental
memory dump all mem.dmp
```

Dump memory after e.g. 10 minutes of inactivity, then, check if sensitive data is still in the memory. See section [4. Inspect Files](#4-inspect-files).

Search memory directly:

```fundamental
memory search "somestring" --string
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

Monitor pasteboard:

```fundamental
ios pasteboard monitor
```

You can also dump pasteboard with [cycript](#dump-pasteboard).

### Bypasses

Bypass jailbreak detection:

```bash
ios jailbreak disable --quiet

objection -g com.someapp.dev explore --startup-command 'ios jailbreak disable --quiet'
```

Also, on your mobile device, you can use `A-Bypass` in `Settings` application.

---

Bypass SSL pinning:

```bash
ios sslpinning disable --quiet

objection -g com.someapp.dev explore --startup-command 'ios sslpinning disable --quiet'
```

Also, on your mobile device, you can use [SSL Kill Switch 2](#ssl-kill-switch-2) in `Settings` application.

---

Bypass biometrics:

```bash
ios ui biometrics_bypass --quiet

objection -g com.someapp.dev explore --startup-command 'ios ui biometrics_bypass --quiet'
```

Also, you can import [Frida](#frida-scripts) script.

## 8. Repackaging

[SSH](#ssh-to-your-mobile-device) to your mobile device and run the following commands.

Navigate to the application specific directory:

```bash
cd /private/var/containers/Bundle/Application/XXX...XXX/
```

Repackage IPA:

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

If you want to pull decrypted IPA from your mobile device, see section [Pull Decrypted IPA](#pull-decrypted-ipa).

## 9. Other

## Monitor System Log

On your Kali Linux, run the following command:

```fundamental
idevicesyslog -p 1337
```

## Monitor File Changes

[SSH](#ssh-to-your-mobile-device) to your mobile device, download and run [Filemon](http://www.newosxbook.com):

```bash
wget http://www.newosxbook.com/tools/filemon.tgz && tar zxvf filemon.tgz && chmod 777 filemon

./filemon -c -f com.someapp.dev
```

Always look for created and cached files, images/screenshots, etc.

Images/screenshots:

```fundamental
cd /var/mobile/Containers/Data/Application/YYY...YYY/Library/SplashBoard/Snapshots
```

Use `nano` to edit files directly on your mobile device.

## Dump Pasteboard

After copying sensitive data, application should wipe pasteboard after a short period of time.

[SSH](#ssh-to-your-mobile-device) to your mobile device and run the following commands:

```fundamental
cycript -p 1337

[UIPasteboard generalPasteboard].items
```

Press `CTRL + D` to exit.

You can also monitor pasteboard in [Objection](#7-objection).

## Get Provisioning Profile

```fundamental
scp root@192.168.1.10:/private/var/containers/Bundle/Application/XXX...XXX/*.app/embedded.mobileprovision ./

openssl smime -inform der -verify -noverify -in embedded.mobileprovision
```

## Tips and Security Best Practices

Bypass keyboard restriction by copying and pasting data into the input field.

Access tokens should be short lived, and invalidated once the user logs out.

Don't forget to test widgets, push notifications, app extensions, and Firebase.

---

Application should not disclose sensitive data in predictive text (due to incorrectly defined input field type), app switcher, and push notifications.

Application should warn a user when taking a screenshot of sensitive data, as well as, that it is trivial to bypass biometrics authentication if iOS device is jailbroken.
