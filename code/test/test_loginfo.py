#!/usr/bin/python3

import sys
sys.path.append("..")

import syslistener

from syslistener.listener import listener
from syslistener.loginfo import Syslogd,Superfw,Viruslog

sent1 = "<3>syslogd: 2014-12-10 16:23:38 0x0000000000000000 SC3809889426 superfw: pam_sm_setcred"

sent2 = "<5>syslogd: 2014-12-10 16:32:01 0x0000000000000000 SC3809889426 crond: USER root pid 17894 cmd /usr/bin/doupg.sh `/usr/local/bin/superfw sysadmin listpip`"

sent3 = "<5>superfw: 2014-12-10 16:50:49 0x0000000000000000 SC3809889426 admin SC3809889426 下级主管 WEB 192.168.140.83 用户管理超时，强制注销。"

sent4 = "<4>superfw: 2014-12-10 16:23:38 0x0000000000000000 SC3809889426 admin SC3809889426 下级主管 WEB 192.168.140.83 用户认证。"

sent5 = "<2>viruslog: 2014-12-10 16:24:03 0x0103000000000000 SV1313060137 Trojan.Win32.Generic.14B62827 木马 中 未知传毒单位名 111.161.66.157 80 hit 192.168.140.83 59389 http GET&nbsp;http://www.qm123.com.cn/shuazhuaqi.rar<--http://down.zdnet.com.cn/link/43/426146.shtml 338762 "

sent6 = "<2>viruslog: 2014-12-10 16:24:03 0x0103000000000000 1313060137 Trojan.Win32.Generic.14B62827 木马 中 未知传毒单位名 111.161.66.157 80 hit 192.168.140.83 59389 http GET&nbsp;http://www.qm123.com.cn/shuazhuaqi.rar<--http://down.zdnet.com.cn/link/43/426146.shtml 338762 "

if __name__ == '__main__':

    a1 = Syslogd(sent1)
    a1.print()

    print(100*"=")

    a2 = Syslogd(sent2)
    a2.print()

    print(100*"=")

    a3 = Superfw(sent3)
    a3.print()

    print(100*"=")

    a4 = Superfw(sent4)
    a4.print()

    print(100*"=")

    a5 = Viruslog(sent5)
    a5.print()

    print(100*"=")

    a6 = Viruslog(sent6)
    a6.print()

    print(100*"=")

    print("得到所有列名")
    dict1 = a1.logd
    dict2 = a3.logd
    dict3 = a5.logd
    
    print(dict1.keys())
    print(dict2.keys())
    print(dict3.keys())
