# -*- coding: UTF-8 -*-
import frida, sys

jsCode = """

//hook 此方法 a3是一个二级指针
//signed int __fastcall sha1_encode(int a1, int a2, char **a3)
//sprintf(v6, "%s%02x", v6, v8, v9, v10);


Java.perform(function(){
	var resPtr = null;
	var soAddr = Module.findBaseAddress("libm2o_jni.so");
	send('soAddr: ' + soAddr);
	var sha1Addr = soAddr.add(0xA8E8 + 1);
	send('sha1Addr: ' + sha1Addr);
	Interceptor.attach(sha1Addr, {
		onEnter: function (args) {
			//字符串
			send(Memory.readCString(args[0]));
			//长度
			send(args[1].toInt32());
			//返回值为二级指针指针
			resPtr = args[2];
		},
		onLeave: function(retval){
			
			//此处还需要再读一次因为是二级  Memory.readPointer(resPtr)
			var buffer = Memory.readByteArray(Memory.readPointer(resPtr), 40);
			console.log(hexdump(buffer, {
				offset: 0,
				length: 40,
				header: true,
				ansi: false
			}));
		}
	});
	
});

""";

def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)

process = frida.get_remote_device().attach("com.hoge.android.app.fujian")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()