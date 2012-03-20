#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
Created on 2011-6-8 

@author: tianwei

func:IRC 主动发现

fixed:增加功能 1.多线程修改 2.socks代理设置 3.ping设置成异步，提高执行速度
fixed:修改功能 1.nmap引入 2.xml文件分析 3.以前程序结合
'''

import sys,string,time,struct,pprint
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from irc_graphic import Ui_IRC  #图形界面导入
import socks,socket     #socksIPY代理设置
from IRCFound import *
from nmapParse import *
import Parser           #nmap XML解析


class MyForm(QMainWindow):
    def __init__(self,parent=None):
        QWidget.__init__(self,parent)
        self.ui = Ui_IRC()
        self.ui.setupUi(self)
        
        #当前状态量
        self.ipaddr = '127.0.0.1'
        self.port = 0
        self.ipcnt = 0          #ip元组总数量
        self.ipALLlistPrev = []    #ip:port元祖列表 原始列表
        self.ipALLlist = []     #ip:port元祖列表
        self.ipList = []        #ip 列表 
        self.portlist = []      #port 列表
        self.finishedCnt = 0    #完成线程数量 
        self.ipString = ''
        #追加状态量
        self.debugswitch = False    #打印调试开关
        self.proxyswitch = False    #代理调试开关        
        self.threadnum = 1          #开启线程数目
        self.allCnt = 0             #IP元组总数
             
        self.flag = False
        #创建nmap预处理线程，避免屏幕出现假死现象
        self.nmap_thread = NmapParse()
        
        #创建Work线程,用来完成IRC搜索
        self.thread = [Worker() for i in xrange(0,600)]   #最大线程数 600
      
        self.connect(self.ui.btnStart, SIGNAL('clicked()'),self.startwork)    #开始工作信号
        self.connect(self.ui.btnWait, SIGNAL('clicked()'),self.waitwork)      #暂停工作信号
        self.connect(self.ui.btnSave, SIGNAL('clicked()'),self.savework)     #保存记录
        #self.connect(self.ui.btnQuit, SIGNAL('clicked()'),self.savework)     #保存记录
        
    def savework(self):
        #保存调试窗口的ip记录
        msg = time.strftime("%H:%M",time.localtime(time.time()))
        f =open('iprecord.txt','a+')
        f.write('\n<-----------'+msg +'保存-------------->\n')
        #f.write(unicode(self.ui.textBrowser.toPlainText(),'utf-8'))
        f.write((self.ui.textBrowser.toPlainText()).toLocal8Bit())
        f.close()
        self.printmsgOld('\t\t文件保存完毕*_*，请到程序所在目录，打开iprecord.txt文件，使用unicode编码') 

    def waitwork(self):
        #暂停线程
        self.ui.textBrowser.clear();
    
    def updataAll(self):
        #更新所有输入        
        self.ui.cmbSockType.update()
        self.ui.cmbDNS.update()
        self.ui.cbProxySwitch.update()
        self.ui.cbDebugSwitch.update()
        self.ui.editIPAddr.update()
        self.ui.editPort.update()
        self.ui.editUserName.update()
        self.ui.editUserPwd.update()
        self.ui.sBConnTimeOut.update()
        self.ui.sBThreadNums.update()
        self.ui.sBTryConnectNum.update()

    
    def emitFinished(self):
        #检查线程完成情况
        self.finishedCnt += 1
        if self.finishedCnt == self.threadnum:
            print '所有IP完成处理'
            self.printmsgOld('\t\t*_* 恭喜，完成所有IP和端口分析 *_*\t\t')
            self.savework()
            self.finishedCnt = 0        
            
    def LoadAttributes(self):
        self.updataAll()
 
        #线程数
        self.threadnum =string.atoi(str(self.ui.sBThreadNums.text()))    
        #调试开关   
        self.debugswitch = self.ui.cbDebugSwitch.isChecked() 
        self.proxyswitch = self.ui.cbProxySwitch.isChecked()
        if self.proxyswitch == True:                           
            #代理设置
            SOCK_PROXY_TYPE = self.ui.cmbSockType.currentIndex()+1        #代理类型：整型
            if self.ui.editIPAddr.text() != '':
                SOCK_PROXY_addr = str(self.ui.editIPAddr.text())          #代理网址或DNS：String类型
            if self.ui.editPort.text() != '':
                SOCK_PROXY_port = string.atoi(str(self.ui.editPort.text()))                       #代理端口：整形,默认为1080/8080
            if self.ui.editUserName.text() != '':
                SOCK_PROXY_username = str(self.ui.editUserName.text())                  #代理用户名
            if self.ui.editUserPwd.text() != '':
                SOCK_PROXY_password = str(self.ui.editUserPwd.text())                  #代理密码
            #Should DNS queries be preformed on the remote side
            if self.ui.cmbDNS.currentIndex() == 0:
                SOCK_PROXY_rdns = True
            else:
                SOCK_PROXY_rdns = False
        else:
            pass #采用默认值
        #连接次数设置
        ConnectTIMEOUT = string.atof(str(self.ui.sBConnTimeOut.text()))          #默认超时时间
        MaxTryNum = string.atoi(str(self.ui.sBTryConnectNum.text()))             #连接测试次数
        
        #IP地址分析
        buf = str(self.ui.TextIPInput.toPlainText())
        #print buf
        if buf == '':
            self.printmsgOld('IP地址为空！！！')
            return
        #按照行进行处理
        buf = buf.split('\n')
        for every in buf:
            every = every.strip()
            self.ipString = self.ipString + every + ' '
        
    def startwork(self):
        #开始线程
        #step 1 : 界面信息存储
        self.LoadAttributes()
        #step 2 : 调用nmap处理，IP地址需要处理+所有端口扫描
        self.printmsgOld('\t请稍等,调用nmap预处理中...')
        self.connect(self.nmap_thread,SIGNAL("finished()"),self.nmap_process)
        self.connect(self.nmap_thread,SIGNAL("debugPrintOK(QString)"),self.printmsgOld)  #打印调试信息
        self.nmap_thread.render(self.ipString)
    
    def nmap_process(self):
        #完成nmap线程处理
        #step1 ： 分析结果文件
        self.printmsgOld('\t分析nmap结果文件...')
        self.nmapParse()    #日志分析，产生结果文件
        #step2 ： 多线程进行IRC测试 启用绘制线程,制定信号和槽(多线程) 
        self.printmsgOld('\t完成文件分析，进行IRC探测...')
        for i in  range(0,self.threadnum):
            self.thread[i] = Worker()
            self.connect(self.thread[i], SIGNAL("finished()"),self.updateUi)
            self.connect(self.thread[i], SIGNAL("Emitfinished()"),self.emitFinished)
            self.connect(self.thread[i], SIGNAL("terminated()"),self.updateUi)
            self.connect(self.thread[i], SIGNAL("output(bool,QString,int)"),self.showmsg)
            self.connect(self.thread[i], SIGNAL("debugPrint(QString)"),self.printmsgUni)  #打印调试信息
            self.connect(self.thread[i], SIGNAL("debugPrintOK(QString)"),self.printmsgOld)  #打印调试信息  
            self.thread[i].render(self.ipALLlist[i],i)
                
        self.printmsgOld('\t请稍等,正在分析中...') 
    
    def nmapParse(self):        #nmap 文件解析：直接提取IP和port，对于
        #step 1:初始化
        self.parse = Parser.Parser(NMAP_FILENAME)
        print '\nscan session:'
        self.session = self.parse.get_session()
        #step 2:打印nmap扫描信息
        self.printmsgOld('\t\t初步扫描信息....')
        self.printmsgOld('\t\t扫描开始时间：\t %s'%(str(self.session.start_time)))
        self.printmsgOld('\t\t扫描结束时间：\t %s'%(str(self.session.finish_time)))
        self.printmsgOld('\t\ttotal hosts:\t %s'%(str(self.session.total_hosts)))
        self.printmsgOld('\t\t开启主机数量:\t%s'%(str(self.session.up_hosts)))

        #step3:记录每条信息，检测到IRC的直接打印，对于unknow的进行进一步探测
        for host in self.parse.all_hosts():
            for port in host.get_ports('tcp','open'):
                service = host.get_service('tcp',port)
                if 'irc' in service.name or 'IRC' in service.name or 'Irc' in service.name :
                    print '探测到IRC服务'
                    msg = '$[0][ok] ##### ('+ str(host.ip) +':' +str(port)+ ')\t\t\t [Successed]'
                    print msg
                    self.printmsgOld(msg)
                elif service == None or 'unknown' in service.name:
                    tmp = (str(host.ip),string.atoi(str(port)))
                    self.ipALLlistPrev.append(tmp)
        #step4:结束标志
        #print self.ipALLlistPrev
        self.ipALLListParseSimple()   #ip合并
        #print self.ipALLlist
        self.printmsgOld('\t\t需要分析 %d 个可疑端口'%len(self.ipALLlistPrev))
            
    def showmsg(self,flag,ipaddr,port):
        #记录信息

        msg = time.strftime("%H:%M",time.localtime(time.time()))
       
        if flag == True:    #ok
            msg = '$[0][ok] #####[' +msg+'] ('+ipaddr+':' +str(port)+ ')\t\t\t [Successed]'
            print msg
            self.printmsgOld(msg)
        else:
            msg = '$[1][no] \t[' +msg+'] ('+ipaddr+':' +str(port)+ ')\t\t [Failed]'
            print msg
            self.printmsgOld(msg)

    def iptoint(self,ipstr):
        #将ip地址'210.30.95.6'转化为整数:将点分十进制 IP 地址转换成无符号的长整数
        return socket.ntohl(struct.unpack("I",socket.inet_aton(ipstr))[0])  #若用‘i’可能会溢出
    def inttoip(self,ipint):
        #将ip整数地址转化为'210.30.95.6':将无符号长整形转换为点分十进制 IP 地址形式
        
        return socket.inet_ntoa(struct.pack('I',socket.htonl(ipint)))
    def ipParse(self):
        #IP地址分析
        self.printmsgOld('开始进行IP地址获取，请稍等....')
        buf = str(self.ui.TextIPInput.toPlainText())
        #print buf
        if buf == '':
            self.printmsgOld('IP地址为空！！！')
            return
        self.printmsgOld('IP:'+ self.ui.TextIPInput.toPlainText())
        #处理字符串格式为：以回车为行段分隔符，每一行可能有一个IP地址或一个IP网段或一个IP范围
        #连接IP范围的以'-'为分隔符
        buf = buf.split('\n')

        for line in buf:    #检索每一行
            #case 1：仅有一个IP地址
            line = line.strip()
            #print line
            if '-' not in line:
                if line.count('.') == 3:
                    #此处为正常IP地址
                    if 'x' not in line and 'X' not in line:
                        #case 2：简单IP地址，如'192.168.7.32'
                        self.ipList.append(line)
                    else:
                        #case 3：存在'x'，替换符的ip地址，如'192.168.x.x','192.168.1.x','192.160.1.x','192.x.x.x'
                        ipTable =[[],[],[],[]]
                        line = line.split('.')  #以点提取四个部分
                        #形成IP个段散列
                        for i in range(0,len(line)):
                            line[i] = line[i].replace(' ','')   #去除空字符串
                            if 'x' in line[i] or 'X' in line[i]: 
                                #字符串中包含'x'字符串，就需要进行(0-255)的散列
                                #ipTable[i] = range(0,256)   #将0-255值都赋予给ipTable
                                ipTable[i] = [str(j) for j in range(0,256)]     #使用列表推导式
                            else:
                                ipTable[i] = [line[i]]      #此处必须以列表形式，否则无法迭代
                        #组合IP
                        for ip1 in ipTable[0]:
                            for ip2 in ipTable[1]:
                                for ip3 in ipTable[2]:
                                    for ip4 in ipTable[3]:
                                        self.ipList.append(ip1+'.'+ip2+'.'+ip3+'.'+ip4)     #此处需要验证，字符串是否改变
                else:
                    #此处需要处理，ip地址没有写完整的情况，如：'192.168.'，需要进行自动补全
                    print 'IP地址不完全，滤过'
                    self.printmsgOld('IP地址不完全，滤过')
                    
            else:
                #case 4:存在ip范围
                #step1:分割字符串
                line = line.replace(' ','')  #过滤空格
                line = line.split('-')
                if line[0] > line[1]:
                    tmp = line[0]
                    line[0] = line[1]
                    line[1] = tmp
                elif line[0] == line[1]:
                    self.ipList.append(line[0])  
                #step2:进行字符串替换,小IP替换成0，大IP替换成255，同时对不符合规定的ip进行规范
                line[0] = line[0].split('.')
                line[1] = line[1].split('.')
                line0 = ''
                line1 = ''
                for i in range(0,len(line[0])):
                    if 'x' in line[0][i]:line[0][i] = '0'
                    if string.atoi(line[0][i])>255:line[0][i] = '255'
                    line0 = line0 + line[0][i] + '.' 
                for i in range(0,len(line[1])):
                    if 'x' in line[1][i]:line[1][i] = '255'
                    if string.atoi(line[1][i])>255:line[1][i] = '255'
                    line1 = line1 + line[1][i] + '.' 
                #step3:检索范围
                
                ipstart = self.iptoint(line0.rstrip('.'))
                ipend   = self.iptoint(line1.rstrip('.')) + 1
                
                while ipstart < ipend:
                    #print self.inttoip(ipstart)
                    self.ipList.append(self.inttoip(ipstart))
                    ipstart +=1
        self.printmsgOld('完成IP地址获取') 
                                      
    def portParse(self):
        #PORT分析
        self.printmsgOld('开始进行Port端口获取，请稍等...')
        buf = str(self.ui.TextPortInput.toPlainText())
        #print buf
        if buf == '':
            self.printmsgOld('PORT为空！！！')
            return
        self.printmsgOld('Port:' + buf)
        
        #处理字符串格式 以回车符作为行分割,不支持行的连接符
        #','为基本处理，支持'-'范围port 
        buf = buf.split('\n')   #行分割 
        for line in buf:
            line = line.split(' ')  #以' '空格分隔每个port
            for word in line:
                #去除空格项干扰
                if word == '':continue 
                if word.find('-') != -1: #找到以-为分隔符的端口号
                    tmp = word.split('-')
                    if tmp[0] == '':continue
                    tmp[0] = tmp[0].strip()
                    tmp[1] = tmp[1].strip()
                    if tmp[0] > tmp[1]:
                        max = tmp[0]
                        min = tmp[1]
                    elif tmp[1] >= tmp[0]:
                        min = tmp[0]
                        max = tmp[1] 
                    min = string.atoi(min)
                    max = string.atoi(max)
                    self.portlist.append(min)                         
                    while min < max:
                        min += 1
                        self.portlist.append(min)
                else:
                    
                    self.portlist.append(string.atoi(word))
        self.printmsgOld('完成Port端口获取')
    
    def ipALLListParseSimple(self):     #ip聚合 第二个版本
        #根据线程数进行划分
        self.allCnt = len(self.ipALLlistPrev)
        pic = len(self.ipALLlistPrev) / self.threadnum +1   #每一组IP列表的数量，最后一个分组收集所有
        grpCnt = 0      #线程分组
        tupleCnt = 0    #每个组ip个数
        #初始化二维列表
        self.ipALLlist = [[] for i in xrange(0,self.threadnum) ]
        for every in self.ipALLlistPrev:
            if grpCnt == self.threadnum -1:
                #最后一组,不用进一步处理
                self.ipALLlist[grpCnt].append(every)
            elif tupleCnt < pic and  grpCnt <self.threadnum -1:
                self.ipALLlist[grpCnt].append(every)
                tupleCnt += 1
            else:
                grpCnt += 1
                tupleCnt = 1
                self.ipALLlist[grpCnt].append(every)
            
        
    def ipALLListParse(self):
        #根据线程数进行划分
        #进行结合，将两个列表进行交叉结合
        self.allCnt = len(self.ipList) * len(self.portlist)
        pic = self.allCnt / self.threadnum +1     #每一组IP列表的数量，最后一个分组收集所有
        grpCnt = 0      #线程分组
        tupleCnt = 0    #每个组ip个数
        #初始化二维列表
        self.ipALLlist = [[] for i in xrange(0,self.threadnum) ]
        for ip in self.ipList:
            for port in self.portlist:
                if grpCnt == self.threadnum -1:     
                    #最后一组,不用进一步处理
                    self.ipALLlist[grpCnt].append((ip,port))
                elif tupleCnt < pic and grpCnt <self.threadnum -1:
                    self.ipALLlist[grpCnt].append((ip,port))
                    tupleCnt += 1
                else:
                    grpCnt += 1
                    tupleCnt = 1
                    self.ipALLlist[grpCnt].append((ip,port)) 
    
    def updateUi(self):
        #更新界面,在work线程完成全部操作时被触发，同时恢复窗口状态
        self.ui.btnStart.setEnabled(True)
        self.ui.btnSave.setEnabled(True)
        self.ui.btnWait.setEnabled(True)
        self.ui.btnQuit.setEnabled(True)
        self.ui.textBrowser.update()
    def printmsgOld(self,str):          #主线程中的打印，无调试开关功能
        str = str + ' '
        str = unicode(str,'utf-8')      #unicode中文显示
        self.ui.textBrowser.append(str)
        self.ui.textBrowser.update()
    def printmsgUni(self,str):          #子线程中的打印，有调试开关功能
        if self.debugswitch:
            self.ui.textBrowser.append(str)
            self.ui.textBrowser.update()
        else:
            pass
    def printmsg(self,str):             #子线程中的打印，有调试开关功能
        if self.debugswitch:
            str = unicode(str,'utf-8')      #unicode中文显示
            self.ui.textBrowser.append(str)
            self.ui.textBrowser.update()
        else:
            pass

       

            
if __name__ == '__main__':
    app = QApplication(sys.argv)
    myapp = MyForm()
    myapp.show()
    sys.exit(app.exec_())

