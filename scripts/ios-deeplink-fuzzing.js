/************************************************************************
 * Name: iOS Deeplink Fuzzing
 * OS: iOS
 * Author: @dki (Credits to the author!)
 * Source: https://codeshare.frida.re/@dki/ios-url-scheme-fuzzing
 * Edited: https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/scripts/ios-deeplink-fuzzing.js (heavy rebase)
 ************************************************************************
 *
 * Usage:
 *     frida -U --no-pause -l ios-deeplink-fuzzing.js -f com.someapp.dev
 *
 * Get the hooked app's URL schemes:
 *     getSchemes();
 *
 * Open a URL (deeplink) system-wide:
 *     openURL("somescheme://com.someapp.dev/somepath");
 *
 * Get all apps for a given URL scheme:
 *     getApps("somescheme");
 *
 * Emulate a single home button click (for app backgrounding):
 *     homeSinglePress();
 *
 * Move all crash logs matching the app's name to "/tmp/" directory:
 *     moveCrashLogs("someapp");
 *
 * Specify a wordlist to use for fuzzing:
 *     addFuzzStringsFromFile("/tmp/wordlist.txt");
 *
 * Fuzz a URL (deeplink) - wehere '{0}' is the placeholder for insertion point:
 *     fuzz("somescheme://com.someapp.dev/action?param={0}");
 *
 * You might want to call 'openURL()' once for the target URL (deeplink) before fuzzing to dismiss any prompt that might appear:
 *     openURL("somescheme://com.someapp.dev/action");
 *     fuzz("somescheme://com.someapp.dev/action?param={0}");
 *
 ************************************************************************/
function getSchemes() {
	var dictionary = ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleURLTypes");
	if (!dictionary) {
		console.log("Hooked app does not have any URL schemes.");
	} else {
		dictionary = dictionary.objectAtIndex_(0);
		var keys = dictionary.allKeys();
		for (var i = 0; i < keys.count(); i++) {
			var key = keys.objectAtIndex_(i);
			if (key == "CFBundleURLName") {
				console.log("URL Scheme Name: " + dictionary.objectForKey_(key));
			} else if (key == "CFBundleURLSchemes") {
				var schemes = [];
				var tmp = dictionary.objectForKey_(key);
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
function getApps(scheme) {
	var apps = [];
	var tmp = ObjC.classes.LSApplicationWorkspace.defaultWorkspace().applicationsAvailableForHandlingURLScheme_(scheme);
	for (var i = 0; i < tmp.count(); i++) {
		apps.push(tmp.objectAtIndex_(i).bundleExecutable());
	}
	return apps;
}
function homeSinglePress() {
	var controller = ObjC.classes.SBUIController;
	if (controller) {
		var version = ObjC.classes.UIDevice.currentDevice().systemVersion().toString();
		ObjC.schedule(ObjC.mainQueue, function() {
			if (version.startsWith("9")) {
				controller.sharedInstance().clickedMenuButton();
			} else {
				// doesn't work on iOS 13, need to find a solution; should work on iOS 10 and 11
				controller.sharedInstance().handleHomeButtonSinglePressUp();
			}
		});
	}
}
function moveCrashLogs(app) {
	var fm = ObjC.classes.NSFileManager.defaultManager();
	var dir = "/private/var/mobile/Library/Logs/CrashReporter/";
	var predicate = ObjC.classes.NSPredicate.predicateWithFormat_("SELF like \"" + app + "*.ips\"");
	var files = fm.contentsOfDirectoryAtPath_error_(dir, NULL).filteredArrayUsingPredicate_(predicate);
	for (var i = 0; i < files.count(); i++) {
		var file = files.objectAtIndex_(i);
		fm.moveItemAtPath_toPath_error_(dir + file, "/tmp/" + file, NULL);
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
	"0.00",
	"-1",
	"1",
	"NaN",
	"-NaN",
	"Infinity",
	"-Infinity",
	"inf",
	"-inf",
	"0b0",
	"0x0",
	"0b00111101110011001100110011001101",
	"0x1.999999999999ap-4",
	"&h00",
	"&hff",
	"0.00000000000000000000000000000000000000000000000001",
	"1e-50",
	"0e0",
	"true",
	"false",
	"+1",
	"0e-1",
	"0e1",
	"null",
	"None",
	"nil",
	"An Array",
	"%20%090",
	"0%20%00%00",
	"-2147483648",
	"2147483647",
	"4294967295",
	"-2147483649",
	"2147483648",
	"4294967296",
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
function addFuzzStringsFromFile(path) {
	var fm = ObjC.classes.NSFileManager.defaultManager();
	if (!fm.isReadableFileAtPath_(path)) {
		console.error("Cannot read the wordlist. Make sure the wordlist is on the iOS device and has the read permission!");
	} else {
		var lines = ObjC.classes.NSString.stringWithContentsOfFile_(path, "NSUTF8StringEncoding", NULL).componentsSeparatedByString_("\n");
		if (!lines.count()) {
			console.warn("Wordlist is empty! Moving on with the built-in list...");
		} else {
			fuzzStrings.length = 0;
			for (var i = 0; i < lines.count(); i++) {
				fuzzStrings.push(lines.objectAtIndex_(i));
			}
			console.log("Wordlist has been loaded successfully.");
		}
	}
}
function fuzz(url) {
	var apps = getApps(url.split('://')[0]);
	if (apps.length > 1) {
		console.error("Multiple apps handle this URL scheme, script will now exit!\nApps: [" + apps.join(", " + "]"));
		return;
	}
	var app = apps[0];
	function Fuzzer(url, app, iter, sleep) {
		this.url = url;
		this.app = app;
		this.iter = iter;
		this.sleep = sleep;
	}
	Fuzzer.prototype.checkForCrash = function(done) {
		homeSinglePress();
		if (moveCrashLogs(this.app)) {
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
		ObjC.classes.NSThread.sleepForTimeInterval_(this.sleep);
		this.checkForCrash(iter.done);
	};
	console.warn("Monitoring crashes for \"" + app + "\"...");
	var count = moveCrashLogs(app);
	if (count) {
		console.warn("Number of crash logs moved to \"/tmp/\": " + count.toString());
	}
	var fuzzer = new Fuzzer(url, app, fuzzStrings.iter(), 2); // change the sleep between attempts here
	fuzzer.fuzz();
}
setTimeout(function() {
	if (ObjC.available) {
		console.log("");
		// --------------------
		getSchemes();
		// --------------------
		// modify the code below as necessary, you can also paste the whole above code directly into Frida and call each method as needed
		// openURL("somescheme://com.someapp.dev/action");
		// addFuzzStringsFromFile("/tmp/wordlist.txt"); // load fuzz strings from a wordlist
		// fuzzStrings.push("somestring");              // append an additional fuzz string
		// fuzz("somescheme://com.someapp.dev/action?param={0}");
	} else {
		console.log("Objective-C Runtime is not available!");
	}
}, 250);
