Plugin: jsonlog
===========

Summary
-------

`jsonlog`插件用于进行json格式的日志记录，所有插件的输出信息都可以通过`jsonlog`插件进行记录。其他插件可以采用回调的方式，将要记录的信息通过回调函数类型传递。一般的，回调函数中至少包含(CPUState *env，uint64_t curr_instr)两种信息。其中curr_instr= rr_get_guest_instr_count()，使用该API需要包含头文件extern "C" { #include "panda/rr/rr_log.h"}。例如插件A想记录某些信息到json中，步骤如下：

发出回调消息的插件A：

```c
#include "panda/plugin_plugin.h"
#include "A.h"
extern "C" {
PPP_PROT_REG_CB(on_example);
}

PPP_CB_BOILERPLATE(on_example);

// 发出回调消息的那一行
PPP_RUN_CB(on_example, args**);

//插件的头文件A.h里面加上声明
typedef void (*on_example_t)(args**);
```

接收处理回调消息的插件jsonlog中需要包含插件A的头文件，on_func函数用来处理接收的信息：

```c
#include "panda/plugin_plugin.h"

extern "C" {
#include "A/A.h"
}

// 在bool init_plugin(void *self) 函数中注册, on_func是处理消息的函数名
PPP_REG_CB("A", on_example, on_func);
```

Arguments
---------

* `name`: string, 默认为"jsonlog"。该参数指定生成的json格式日志文件的名称，即`<name>.json`

Dependencies
------------

`jsonlog` 依赖 `osi` 来确定当前记录的日志的虚拟机的基本的信息。


Example
-------
```shell
./qemu-system-x86_64 -m 2048M -usbdevice tablet -replay HeartBleed -os linux-32-ubuntu:3.5.0-37-generic  -panda stringsearch:name=keyword -panda tstringsearch -panda tainted_net:query_outgoing_network=true,file=keyword_tainted.csv -panda jsonlog
```
