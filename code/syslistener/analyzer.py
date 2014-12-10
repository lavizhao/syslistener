'''
解析数据的类基本都放这里了
'''

from .loginfo import Syslogd,Superfw,Viruslog

class log_analyzer:
    def __init__(self):
        #定义类型, 瑞星的log就三种, 所以就定义四种类型, 可能单词有拼写错误...
        self.SYSLOGD = 0
        self.SUPERFW = 1
        self.VIRUSLOG = 2
        self.UNKNOWN = 3

        self.__type_string = ['syslogd','superfw','viruslog','unknown']
        
        self.__syslogd = self.__type_string[self.SYSLOGD]
        self.__superfw = self.__type_string[self.SUPERFW]
        self.__viruslog = self.__type_string[self.VIRUSLOG]
        

        
    #判断日志类型
    #现在我见过的类型有三种, 所以会返回四种
    def log_type(self,log):
        #从log的第三个字母开始截, 可能傻逼了点
        rlog = log[3:]

        if rlog.startswith(self.__syslogd):
            return self.SYSLOGD
        elif rlog.startswith(self.__superfw):
            return self.SUPERFW
        elif rlog.startswith(self.__viruslog):
            return self.VIRUSLOG
        else:
            return self.UNKNOWN


    def get_log_type_string(self,log):
        logtype = self.log_type(log)
        return self.__type_string[logtype]

    #返回log的class
    def get_log(self,log):
        logtype = self.log_type(log)
        
        if logtype == self.SYSLOGD:
            return Syslogd(log)
        elif logtype == self.SUPERFW:
            return Superfw(log)
        elif logtype == self.VIRUSLOG:
            return Viruslog(log)
        else:
            print("error in detect type")
            return None
            

    #返回log的sql语句
    def get_insert_string(self,log,ip,port):
        tlog = self.get_log(log)

        #得到log的dict
        logd = tlog.logd

        #得到log的table name
        tbl_name = self.get_log_type_string(log)+"_tbl"

        key_string,value_string = "",""
        for k in logd:
            v = logd[k]
            
            ks = "%s,"%(k)
            
            if k != 'virus_size' or k!='severity':
                vs = "\'%s\',"%(v)
            else :
                vs = "%s,"%(v)

            key_string += ks
            value_string += vs

        sql = 'insert into %s(%s,router_ip,router_port) values(%s,\'%s\',\'%s\')'%(tbl_name,key_string[:-1],value_string[:-1],ip,port)
            
        return sql
