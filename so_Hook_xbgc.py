# -*- coding: UTF-8 -*-
import frida, sys

jsCode = """

//使用地址的方式
Java.perform(function(){
	var resPtr = null;
	var soAddr = Module.findBaseAddress("libwtf.so");
	send('soAddr: ' + soAddr);
	var MD5DigestAddr = soAddr.add(0xC90 + 1);


	/*
	//new 一个so层的函数 名称是func
	var func = new NativeFuncation(MD5DigestAddr,'pointer',['pointer','pointer']);
	//创建env
	var env = Java.vm.getEnv();
	//创建一个内容为xxx的指针
	var jstr = env.newStringUtf('xxxx');
	//调用函数
	var cstr = func(env.jstr);
	*/


	send('MD5DigestAddr: ' + MD5DigestAddr);
	Interceptor.attach(MD5DigestAddr, {
		onEnter: function (args) {
			//看看这个字符串是什么样子
			send("Memory.readCString(args[0]) ："+Memory.readCString(args[0]));
			send(args[1]);
			resPtr = args[2];
		},
		onLeave: function(retval){
			var buffer = Memory.readByteArray(resPtr, 16);
			console.log("resPtr ："+ hexdump(buffer, {
				offset: 0,
				length: 16,
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

process = frida.get_remote_device().attach("com.sichuanol.cbgc")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()
