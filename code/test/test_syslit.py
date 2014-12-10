#!/usr/bin/python3

'''
测试监听器好使不好使
'''

import sys
sys.path.append("..")

import syslistener

from syslistener.listener import listener

if __name__ == '__main__':
    print("test")
    print("开始测试初始化监听器")

    lis = listener()

    print("开始监听")
    lis.run()

    print("结束测试")

