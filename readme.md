# 让我康康
* 通过禁止目标进程关闭句柄的方式保留其所有打开过的文件句柄。
* 使用ProcessHacker等工具即可看到目标进程打开过哪些文件
* AC有没有偷偷扫描硬盘？读取了什么？一看便知

## 警告
使用本工具肯定会被封号。Use at your own risk。

## 提示
*本工具只能拦截使用标准windowsAPI销毁的句柄，对于枚举硬盘文件，还有一种是通过NTFS USN的方式，可以直接取得文件名，内容等信息，本工具不支持拦截显示。（事实上很多国产AC也内置了这个扫描硬盘的方法）因此开启本工具后ProcessHacker等工具展示的文件列表不代表全部其读取的文件*
*若要记录使用NTFS USN枚举的文件，ring3下需要hook DeviceIoControl函数*

## 使用方法
开始本工具，输入目标进程窗口句柄（16进制），回车确认。

目标进程会弹出MessageBox，点击确认后，本工具开始工作。

一段时间后使用ProcessHacker等工具查看目标进程句柄表。

## 原理
* 本工具基于LoadEXE构建，没有驱动，能够无视没有minifilter的AntiCheat保护进行。
* 除用于游戏，本工具也可用于其它进程
* 使用Minhook勾住NtClose以防关闭句柄
* 据观察，仅packman自实现syscall调用NtClose，其它AC均直接调用CloseHandle，所以本工具目前对大部分AC有效
* 仅保留文件句柄，其它句柄可以正常关闭
* 排除了拥有写权限的文件
* 排除了在目标进程目录下或windows目录下的文件
* 同一文件句柄仅保留一次

## 协议
### LetMeSeeSee
EPL
### LoadEXE
MIT
