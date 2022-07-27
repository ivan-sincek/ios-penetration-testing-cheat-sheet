/************************************************************************
 * Name: iOS URL Scheme Fuzzing
 * OS: iOS
 * Author: @dki (Credits to the author!)
 * Source: https://codeshare.frida.re/@dki/ios-url-scheme-fuzzing
 * Edited: https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/scripts/ios-url-scheme-fuzzing.js
 ************************************************************************
 *
 * Fuzz iOS URL scheme:
 *     frida -U --no-pause -l ios_url_scheme_fuzzing.js -f com.someapp.dev
 *
 * Dump all registered URL schemes from app:
 *     dumpSchemes();
 *
 * Open the specified URL (deeplink):
 *     openURL("somescheme://app.someapp.dev/action");
 *
 * Find the executable name for the specified URL scheme:
 *     bundleExecutableForScheme("somescheme");
 *
 * Emulate a single home button click (for app backgrounding):
 *     homeSinglePress();
 *
 * Move all crash logs matching a particular string to '/tmp/' directory:
 *     moveCrashLogs("someapp");
 *
 * File on iOS device to fuzz URL scheme:
 *     addFuzzStringsFromFile("/tmp/somefile.txt");
 *
 * Fuzz the specified URL scheme - use '{0}' as the placeholder for insertion points:
 *     fuzz("somescheme://app.someapp.dev/action?param={0}");
 *
 * You will typically want to call openURL() for the target scheme once before fuzzing to dismiss the prompt that appears the first time:
 *     openURL("somescheme://app.someapp.dev/action");
 *     fuzz("somescheme://app.someapp.dev/action?param={0}");
 *
 ************************************************************************/
 function dumpSchemes() {
	var dictionary = ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleURLTypes");
	if (!dictionary) {
		console.log("No URL schemes are defined by the app.");
	} else {
		dictionary = dictionary.objectAtIndex_(0);
		var keys = dictionary.allKeys();
		for (var i = 0; i < keys.count(); i++) {
			var key = keys.objectAtIndex_(i);
			if (key == "CFBundleURLName") {
				console.log("URL Scheme Name: " + dictionary.objectForKey_(key));
			} else if (key == "CFBundleURLSchemes") {
				var schemes = [];
				var tmp = dictionary.objectForKey_("CFBundleURLSchemes");
				for (var j = 0; j < tmp.count(); j++) {
					schemes.push(tmp.objectAtIndex_(j));
				}
				console.log("URL Schemes: [" + schemes.join(", ") + "]");
			}
		}
	}
}
function openURL(url) {
	var workspace = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
	return workspace.openSensitiveURL_withOptions_(ObjC.classes.NSURL.URLWithString_(url), null);
}
function bundleExecutableForScheme(scheme) {
	var bundleExecutable = null;
	var apps = ObjC.classes.LSApplicationWorkspace.defaultWorkspace().applicationsAvailableForHandlingURLScheme_(scheme);
	if (apps.count() == 1) {
		bundleExecutable = apps.objectAtIndex_(0).bundleExecutable();
	}
	return bundleExecutable;
}
function homeSinglePress() {
	var version = ObjC.classes.UIDevice.currentDevice().systemVersion().toString();
	if (version.startsWith("9")) {
		ObjC.schedule(ObjC.mainQueue, function() { ObjC.classes.SBUIController.sharedInstance().clickedMenuButton(); });
	} else {
		// doesn't work on iOS 13, need to find a solution; should work on iOS 10 and 11
		ObjC.schedule(ObjC.mainQueue, function() { ObjC.classes.SBUIController.sharedInstance().handleHomeButtonSinglePressUp(); });
	}
}
function moveCrashLogs(appName) {
	var predicate = ObjC.classes.NSPredicate.predicateWithFormat_("SELF like \"" + appName + "*.ips\"");
	var fm = ObjC.classes.NSFileManager.defaultManager();
	var files = fm.contentsOfDirectoryAtPath_error_("/private/var/mobile/Library/Logs/CrashReporter/", NULL).filteredArrayUsingPredicate_(predicate);
	for (var i = 0; i < files.count(); i++) {
		var file = files.objectAtIndex_(i);
		fm.moveItemAtPath_toPath_error_("/private/var/mobile/Library/Logs/CrashReporter/" + file, "/tmp/" + file, NULL);
	}
	return files.count();
}
if (!String.format) {
	String.format = function(format) {
		var args = Array.prototype.slice.call(arguments, 1);
		return format.replace(/{(\d+)}/g, function(match, number) {
			return typeof args[number] != 'undefined' ? args[number] : match;
		});
	};
}
// add or modify fuzz strings here
var fuzzStrings = [
	"0",
	"000",
	"-1",
	"1",
	"NaN",
	"-NaN",
	"Infinity",
	"-Infinity",
	"inf",
	"-inf",
	"0b100010011000",
	"0b00111101110011001100110011001101",
	"0x898",
	"0x1.999999999999ap-4",
	"&h00",
	"&hff",
	"0.1",
	"0.00000000000000000000000000000000000000000000000001",
	"true",
	"false",
	"null",
	"None",
	"nil",
	"An Array",
	"%20",
	"%20test",
	"%20%090",
	"0%20%00%00",
	Array(256).join("9"),
	Array(512).join("9"),
	Array(1024).join("9")
];
fuzzStrings.iter = function() {
	var index = 0;
	var data = this;
	return {
		next: function() {
			return {
				value: data[index],
				done: index++ == (data.length - 1)
			};
		}
	}
};
function addFuzzStringsFromFile(file) {
	var fm = ObjC.classes.NSFileManager.defaultManager();
	if (!fm.isReadableFileAtPath_(file)) {
		console.error("Cannot read the file. The file must be on the iOS device!");
	} else {
		var file = ObjC.classes.NSString.stringWithContentsOfFile_(file, "NSUTF8StringEncoding", NULL).componentsSeparatedByString_("\n");
		if (file.count() < 1) {
			console.error("File is empty! Continuing with the default wordlist.");
		} else {
			fuzzStrings.length = 0;
			for (var i = 0; i < file.count(); i++) {
				fuzzStrings.push(file.objectAtIndex_(i));
			}
			console.log("Wordlist has been loaded successfully.");
		}
	}
}
function fuzz(url) {
	var appName = bundleExecutableForScheme(url.split(':')[0]);
	if (!appName) {
		console.error("Could not determine which app handles this URL!");
		return;
	}
	function Fuzzer(url, appName, iter) {
		this.url = url;
		this.appName = appName;
		this.iter = iter;
	}
	Fuzzer.prototype.checkForCrash = function(done) {
		homeSinglePress();
		if (moveCrashLogs(this.appName) > 0) {
			console.error("Crashed!");
		}
		if (!done) {
			this.fuzz();
		}
	};
	Fuzzer.prototype.fuzz = function() {
		var iter = this.iter.next();
		var fuzzedURL = String.format(this.url, iter.value);
		if (openURL(fuzzedURL)) {
			console.log("Opened URL: " + fuzzedURL);
		} else {
			console.error("URL refused by SpringBoard: " + fuzzedURL);
		}
		ObjC.classes.NSThread.sleepForTimeInterval_(3);
		this.checkForCrash(iter.done);
	};
	console.warn("Monitoring crashes for \"" + appName + "\"...");
	if (moveCrashLogs(appName) > 0) {
		console.warn("Moved one or more logs to \"/tmp/\" before fuzzing!");
	}
	var fuzzer = new Fuzzer(url, appName, fuzzStrings.iter());
	fuzzer.fuzz();
}
/*
setTimeout(function() {
	if (ObjC.available) {
		console.log("");
		// modify the code below as necessary, you can also paste the whole source code directly into Frida and call the methods as you like
		dumpSchemes();
		openURL("somescheme://app.someapp.dev/action");
		addFuzzStringsFromFile("/tmp/somefile.txt"); // add fuzz strings from a file on iOS device
		fuzzStrings.push("somestring");              // add a fuzz string
		fuzz("somescheme://app.someapp.dev/action?param={0}");
	} else {
		console.log("Objective-C Runtime is not available!");
	}
}, 250);
*/
console.log("");
dumpSchemes();
