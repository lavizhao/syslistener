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

    a = Syslogd(sent1)
    a.print()

    print(100*"=")

    a = Syslogd(sent2)
    a.print()

    print(100*"=")

    a = Superfw(sent3)
    a.print()

    print(100*"=")

    a = Superfw(sent4)
    a.print()

    print(100*"=")

    a = Viruslog(sent5)
    a.print()

    print(100*"=")

    a = Viruslog(sent6)
    a.print()

    print(100*"=")
