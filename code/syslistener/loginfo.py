'''
存储三个log的类
'''

from abc import ABCMeta, abstractmethod

#基类其他几个类都需继承
class loginfo(metaclass=ABCMeta):
    
    #log_sentence 是原生的log句子
    #这个存起来的目的是因为挂了可以很方便的调试
    def __init__(self,log_sentence):
        self.__log_orign = log_sentence
        

    #一下是get类函数

    def get_log_orign(self):
        return self.__log_orign
        
    #抽象方法, 分析句子的各个成分, 返回存到个字典里面
    @abstractmethod
    def analyze(self):
        pass

    @abstractmethod
    def print(self):
        pass
        
class Syslogd(loginfo):
            
    def __init__(self,log_sentence):
        loginfo.__init__(self,log_sentence)

        logd = self.analyze(log_sentence)

        self.__severity = logd['severity']
        self.__time = logd['time']
        self.__node_id = logd['node_id']
        self.__device_id = logd['device_id']
        self.__description = logd['description']

        self.logd = logd
        self.logd['orign'] = self.get_log_orign()

    def analyze(self,logsent):
        result = {}
        
        #获得严重程度
        result['severity'] = int(logsent[1])
        
        tlog = logsent.split()
        
        #获得时间
        ymd,ctime = tlog[1],tlog[2]
        result['time'] = ymd+" "+ctime

        #获得节点id
        result['node_id'] = tlog[3]

        #获得设备id
        result['device_id'] = tlog[4]

        #获得描述信息
        result['description'] = "NULL"

        if len(tlog) >= 4:
            tlog = tlog[5:]

        tlog = ' '.join(tlog)
        result['description'] = tlog

        return result


    def print(self):
        print("原来的句子: %s"%(self.get_log_orign()))
        print("严重程度 : %s"%(self.__severity))
        print("时间 : %s"%(self.__time))
        print("节点id : %s"%(self.__node_id))
        print("设备id : %s"%(self.__device_id))
        print("描述信息 : %s"%(self.__description))
        

class Superfw(loginfo):
            
    def __init__(self,log_sentence):
        loginfo.__init__(self,log_sentence)

        logd = self.analyze(log_sentence)

        self.__severity = logd['severity']
        self.__time = logd['time']
        self.__node_id = logd['node_id']
        self.__device_id = logd['device_id']
        self.__usr_name = logd['usr_name']
        self.__system_device_id = logd['system_device_id']
        self.__permission = logd['permission']
        self.__login_type = logd['login_type']
        self.__login_ip = logd['login_ip']
        self.__operate_content = logd['operate_content']

        self.logd = logd
        self.logd['orign'] = self.get_log_orign()

    def analyze(self,logsent):
        result = {}
        
        #获得严重程度
        result['severity'] = int(logsent[1])
        
        tlog = logsent.split()
        
        #获得时间
        ymd,ctime = tlog[1],tlog[2]
        result['time'] = ymd+" "+ctime

        #获得节点id
        result['node_id'] = tlog[3]

        #获得设备id
        result['device_id'] = tlog[4]

        #获得用户名
        result['usr_name'] = tlog[5]

        #获得系统设备名
        result['system_device_id'] = tlog[6]

        #获得权限
        result['permission'] = tlog[7]

        #获得登陆方式
        result['login_type'] = tlog[8]

        #获得登陆IP
        result['login_ip'] = tlog[9]

        #获得操作内容
        result['operate_content'] = tlog[10]

        return result


    def print(self):
        print("原来的句子: %s"%(self.get_log_orign()))
        print("严重程度 : %s"%(self.__severity))
        print("时间 : %s"%(self.__time))
        print("节点id : %s"%(self.__node_id))
        print("设备id : %s"%(self.__device_id))
        print("用户名 : %s"%(self.__usr_name))
        print("系统设备id : %s"%(self.__system_device_id))
        print("权限 : %s"%(self.__permission))
        print("登陆方式 : %s"%(self.__login_type))
        print("登陆IP : %s"%(self.__login_ip))
        print("操作内容 :%s"%(self.__operate_content))


class Viruslog(loginfo):
    def __init__(self,log_sentence):
        loginfo.__init__(self,log_sentence)

        logd = self.analyze(log_sentence)

        self.__severity = logd['severity']
        self.__time = logd['time']
        self.__node_id = logd['node_id']
        self.__device_id = logd['device_id']
        self.__virus_name = logd['virus_name']
        self.__threat_type = logd['threat_type']
        self.__danger_type = logd['danger_type']
        
        self.__spread_virus_device_name = logd['spread_virus_device_name']
        self.__spread_virus_device_ip = logd['spread_virus_device_ip']
        self.__spread_virus_device_port = logd['spread_virus_device_port']
        
        self.__get_virus_device_name = logd['get_virus_device_name']
        self.__get_virus_device_ip = logd['get_virus_device_ip']
        self.__get_virus_device_port = logd['get_virus_device_port']
        self.__get_virus_device_protocol = logd['get_virus_device_protocol']
        self.__virus_info = logd['virus_info']
        self.__virus_size = logd['virus_size']

        self.logd = logd
        self.logd['orign'] = self.get_log_orign()
        
    def analyze(self,logsent):
        result = {}
        
        #获得严重程度
        result['severity'] = int(logsent[1])
        
        tlog = logsent.split()
        
        #获得时间
        ymd,ctime = tlog[1],tlog[2]
        result['time'] = ymd+" "+ctime

        #获得节点id
        result['node_id'] = tlog[3]

        #获得设备id
        result['device_id'] = tlog[4]

        #获得病毒名称
        result['virus_name'] = tlog[5]

        #获得威胁类别
        result['threat_type'] = tlog[6]

        #获得危险类别
        result['danger_type'] = tlog[7]

        #获得传毒单位名
        result['spread_virus_device_name'] = tlog[8]

        #获得传毒ip
        result['spread_virus_device_ip'] = tlog[9]

        #获得传毒端口
        result['spread_virus_device_port'] = tlog[10]

        #获得受毒单位名
        result['get_virus_device_name'] = tlog[11]

        #获得受毒ip
        result['get_virus_device_ip'] = tlog[12]

        #获得受毒端口
        result['get_virus_device_port'] = tlog[13]

        #获得受毒协议
        result['get_virus_device_protocol'] = tlog[14]

        #获得传毒信息
        result['virus_info'] = tlog[15]

        #获得病毒大小
        result['virus_size'] = tlog[16]

        return result


    def print(self):
        print("原来的句子: %s"%(self.get_log_orign()))
        print("严重程度 : %s"%(self.__severity))
        print("时间 : %s"%(self.__time))
        print("节点id : %s"%(self.__node_id))
        print("设备id : %s"%(self.__device_id))
        print("病毒名称 : %s"%(self.__virus_name))
        print("威胁类别 : %s"%(self.__threat_type))
        print("危险类别 : %s"%(self.__danger_type))
        
        print("传毒单位名 : %s"%(self.__spread_virus_device_name))
        print("传毒ip : %s"%(self.__spread_virus_device_ip))
        print("传毒端口 : %s"%(self.__spread_virus_device_port))
        
        print("受毒单位名 : %s"%(self.__get_virus_device_name))
        print("受毒ip : %s"%(self.__get_virus_device_ip))
        print("受毒端口 : %s"%(self.__get_virus_device_port))
        print("受毒协议 : %s"%(self.__get_virus_device_protocol))
        
        print("传毒信息 : %s"%(self.__virus_info))
        print("文件大小 : %s"%(self.__virus_size))

