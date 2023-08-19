# Frida特征对抗案例2


### 一、资源准备
- com.jingdong.app.mall 12.1.0
- pixel2 android10.0
- frida 14.2.2
### 二、分析思路
使用frida以spawn模式启动，可以发现进程直接崩溃，说明存在反调试
```shell
Spawned `com.jingdong.app.mall`. Resuming main thread!                  
[Pixel 2::com.jingdong.app.mall]-> Process terminated
[Pixel 2::com.jingdong.app.mall]->
```
通常检测逻辑是放在native层的，因此进一步判断是哪个so导致的
```js
function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    console.log("load " + path);
                }
            }
        }
    );
}
```
由so的加载流程可知，so都是是顺序加载，从命令行中当加载libJDMobileSec之后，进程就崩溃了，可以猜测反调试点在libJDMobileSec中
```
Spawned `com.jingdong.app.mall`. Resuming main thread!                  
[Pixel 2::com.jingdong.app.mall]-> load /system/framework/oat/arm/org.apache.http.legacy.odex
load /data/app/com.jingdong.app.mall-OXNoca8Sb7xq1IC0YJW2PA==/oat/arm/base.odex
load /data/app/com.jingdong.app.mall-OXNoca8Sb7xq1IC0YJW2PA==/lib/arm/libJDMobileSec.so
Process terminated
```
同样需要判断具体检测的函数在哪个部分，优先确定JNI_OnLoad的偏移是0x56BC
```js
function hook_dlopen(soName = '') {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    if (path.indexOf(soName) >= 0) {
                        this.is_can_hook = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.is_can_hook) {
                    hook_JNI_OnLoad()
                }
            }
        }
    );
}
 
function hook_JNI_OnLoad(){
    let module = Process.findModuleByName("libJDMobileSec.so")
    Interceptor.attach(module.base.add(0x56BC + 1), {
        onEnter(args){
            console.log("call JNI_OnLoad")
        }
    })
}

setImmediate(hook_dlopen,"libJDMobileSec.so")
```
看到是在JNI_OnLoad之后进程崩溃的，说明检测逻辑应该是JNI_OnLoad里面
```shell
Spawned `com.jingdong.app.mall`. Resuming main thread!                  
[Pixel 2::com.jingdong.app.mall]-> call JNI_OnLoad
Process terminated
```
测试下是否有新起线程检测
```js
function hook_pthread_create(){
    var base = Process.findModuleByName("libJDMobileSec.so").base
    console.log("libJDMobileSec.so --- " + base)
    Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"),{
        onEnter(args){
            let func_addr = args[2]
            console.log("The thread function address is " + func_addr + " offset:" + (func_addr-base).toString(16))
        }
    })
}
```
可以看到有个新起的线程
```shell
Spawned `com.jingdong.app.mall`. Resuming main thread!                  
[Pixel 2::com.jingdong.app.mall]-> call JNI_OnLoad
libJDMobileSec.so --- 0xce055000
The thread function address is 0xce06151d offset:c51d
Process terminated
```
优先nop掉看是否该点是检测点，追溯到JNI_OnLoad方法里面偏移0x688A上
```js
function bypass(){
    let module = Process.findModuleByName("libJDMobileSec.so")
    nop(module.base.add(0x688A))
}
```
nop掉之后还是崩溃，看来检测点可能不是这里或者不止一个，继续尝试其他hook点
```js
function replace_str() {
    var pt_strstr = Module.findExportByName("libc.so", 'strstr');
 
    Interceptor.attach(pt_strstr, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            console.log("strstr-->", str1, str2);
            // console.log('strstr called from:\\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
            // console.log('strstr called from:\\n' + Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
        }
    }); 
}
```
看看字符比较会不会有发现
```shell
strstr--> bb123000-bb222000 r--p 00000000 103:1d 2720259                           /data/app/com.jingdong.app.mall-OXNoca8Sb7xq1IC0YJW2PA==/oat/arm/base.odex
 com.saurik.substrate
strstr called from:\n0xcdf5dbfb libJDMobileSec.so!0xabfb\n0xcdf6e5a1 libJDMobileSec.so!0x1b5a1\n
strstr--> bb222000-bb272000 r--p 00000000 103:06 1437                              /system/framework/oat/arm/org.apache.http.legacy.odex
 re.frida.server/frida-agent-32.so
strstr called from:\n0xcdf5da3f libJDMobileSec.so!0xaa3f\n0xcdf6e5a1 libJDMobileSec.so!0x1b5a1\n
strstr--> bb222000-bb272000 r--p 00000000 103:06 1437                              /system/framework/oat/arm/org.apache.http.legacy.odex
 re.frida.server/frida-agent-64.so
strstr called from:\n0xcdf5da85 libJDMobileSec.so!0xaa85\n0xcdf6e5a1 libJDMobileSec.so!0x1b5a1\n
strstr--> bb222000-bb272000 r--p 00000000 103:06 1437                              /system/framework/oat/arm/org.apache.http.legacy.odex
 com.saurik.substrate
strstr called from:\n0xcdf5dbfb libJDMobileSec.so!0xabfb\n0xcdf6e5a1 libJDMobileSec.so!0x1b5a1\n
strstr--> bb272000-bc06a000 r--p 00000000 103:1d 1032201                           /data/local/tmp/re.frida.server/frida-agent-32.so
 re.frida.server/frida-agent-32.so
strstr called from:\
```
从日志中看出来应该是比较了maps中是否包含frida-agent、substrate等特征，根据堆栈确定调用点大致是在0xaa85、0xabfb这几个偏移上，从ida上看都集中在sub_A934这个函数里面，看看交叉引用的地方
，在JNI_OnLoad中有两处，nop掉看看效果
```js
function bypass(){
    let module = Process.findModuleByName("libJDMobileSec.so")
    nop(module.base.add(0x688A))
    nop(module.base.add(0x623A))
    nop(module.base.add(0x634A))
}
```
nop掉两处后就可以正常调试了，说明sub_A934这个函数就是反调试检测的函数，看看具体sub_A934的函数逻辑是什么

### 三 总结
完整代码看这里[libJDMobileSec.js](https://github.com/tcc0lin/SecCase/blob/main/libJDMobileSec.js)
