import socket
import sys

#这个包的作用是检测字符编码
import chardet

from .read_conf import config

#load config文件
lisconf = config("../../conf/listen.conf")

from .analyzer import log_analyzer

logana = log_analyzer()

from .db import mydb
dba = mydb()

#侦听器
class listener:
    
    def __init__(self):

        #这两个不让其他类访问
        self.__host = lisconf["list_host"]
        self.__port = int(lisconf["list_port"])

        #确定server 的address
        self.server_address = (self.__host,self.__port)

        #这个应该是类的预设值, 这个可以重新设
        self.data_payload = int(lisconf["data_payload"])

    def run(self,display=True):
            

        #建socket
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

        #确保reuse
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

        #绑定端口
        sock.bind(self.server_address)

        indx = 0
        while True:
            print("第%s条信息"%(indx+1))

            data,addr = sock.recvfrom(self.data_payload)
            if data:
                #瑞星原来的是傻逼gbk, 反正应该是转明白了
                data = str(data,encoding="gbk")
                data = data.encode()
                data = str(data,encoding="utf-8")

                #解IP
                ip,port = addr

                if display:
                    print("数据%s"%(data))
                    print("地址 IP:%s 端口:%s"%(ip,port))
                    print("log种类: %s"%(logana.get_log_type_string(data)))
                    loginfo = logana.get_log(data)
                    loginfo.print()
                    dba.insert_tbls(data,ip,port)
                    print(100*"=")
                
            indx += 1
