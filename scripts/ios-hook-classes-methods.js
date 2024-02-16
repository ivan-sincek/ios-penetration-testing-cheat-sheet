/************************************************************************
 * Name: iOS Hook All Classes & Methods
 * OS: iOS
 * Author: @interference-security (Credits to the author!)
 * Source: https://codeshare.frida.re/@interference-security/ios-app-all-classes-methods-hooks
 * Edited: https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/scripts/ios-hook-classes-methods.js
 ************************************************************************/
function print_ex(ex, debug = false) {
	if (debug) { console.error("[!] Exception: " + ex.message); }
}
function get_timestamp() {
	var today = new Date();
	return today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
}
function hook_class_method(class_name, method_name) {
	var hook = ObjC.classes[class_name][method_name];
	Interceptor.attach(hook.implementation, {
		onEnter: function(args) {
			console.log("[+] [" + get_timestamp() + "] " + class_name + " " + method_name);
		}
	});
}
function hook_all_methods_of_all_classes() {
	console.log("[*] Hooking all methods of all classes...");
	var free = new NativeFunction(Module.findExportByName(null, "free"), "void", ["pointer"]);
	var objc_copyClassNamesForImage = new NativeFunction(Module.findExportByName(null, "objc_copyClassNamesForImage"), "pointer", ["pointer", "pointer"]);
	var size = Memory.alloc(Process.pointerSize); Memory.writeUInt(size, 0);
	var ptrClasses = objc_copyClassNamesForImage(Memory.allocUtf8String(ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()), size);
	size = Memory.readUInt(size);
	for (var i = 0; i < size; i++) {
		var className = Memory.readUtf8String(Memory.readPointer(ptrClasses.add(i * Process.pointerSize)));
		if (ObjC.classes.hasOwnProperty(className)) {
			var methods = ObjC.classes[className].$ownMethods;
			for (var j = 0; j < methods.length; j++) {
				try { hook_class_method(className, methods[j]); } catch (ex) { print_ex(ex); }
			}
		}
	}
	free(ptrClasses);
	console.log("[*] Hooking all methods of all classes has finished!");
}
setTimeout(function(){
	if (ObjC.available) {
		setImmediate(hook_all_methods_of_all_classes);
	} else {
		console.log("Objective-C Runtime is not available!");
	}
}, 250);
