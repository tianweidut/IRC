#!/usr/bin/env python
# -*- coding:utf-8 -*-
'''
Created on 2011-6-23

@author: tianwei

func:
'''
import sys,string,time,struct
from PyQt4.QtCore import *
from PyQt4.QtGui import *
import socks,socket     #socksIPY代理设置


#通过import * 将下面所有的变量引入
NICKNAME = 'too009'        #登陆随机信息
CHANNEL = '#acx' 
REALNAME = 'a233'
USERNAME = 'a23'
HOSTNAME = 'a23'
SERVERNAME ='a23'

PROXY_TYPE_SOCKS4_IRC = 1       #IRC socks代理类型
PROXY_TYPE_SOCKS5_IRC = 2
PROXY_TYPE_HTTP_IRC = 3

SOCK_PROXY_TYPE = None               #代理类型：整型
SOCK_PROXY_addr = None              #代理网址或DNS：String类型
SOCK_PROXY_port = None                      #代理端口：整形,默认为1080/8080
SOCK_PROXY_username = None                  #代理用户名
SOCK_PROXY_password = None                  #代理密码
SOCK_PROXY_rdns = True                      #Should DNS queries be preformed on the remote side

ConnectTIMEOUT = 5.0          #默认超时时间
MaxTryNum = 1                  #连接测试次数
RecvSIZE = 1024 
IPCNT = 0                   #IP池数量
irccnt = 3                 #IRC字符串获取试验测试
LONGTIMEOUT = 30            #readbuf 时间 秒

class Worker(QThread):  #使用PyQt中的线程代替Python本身的线程       
    def __init__(self,parent=None):
        QThread.__init__(self,parent)
        self.exiting = False        #保存基本绘制信息，exiting 记录线程工作状态
        self.ipALLlist = []         #ip:port元祖列表

        self.ipcnt = 0
        self.trycnt = 0             #连接测试次数
        self.ircTryCnt = 0
        self.num = 0
    
    #当work线程对象在被销毁的时候，需要停止线程
    def __del__(self):
        self.exiting = True
        self.wait()      
    
    def finishEmit(self):
        #发射完成信号
        self.emit(SIGNAL("Emitfinished()"))
    
    def printEmit(self,str):
        #打印发射信号
        str = unicode('\t[调试信息]','utf-8') + unicode(str,'utf-8')
        self.emit(SIGNAL("debugPrint(QString)"),str)
    def printEmitOK(self,str):
        #打印发射信号
        str = unicode('\t[Finished]','utf-8') + unicode(str,'utf-8')
        self.emit(SIGNAL("debugPrintOK(QString)"),str)
              
    def render(self,ipAllList,n):
        #print '\t\t[Add]'+str(ipAllList)+'\t'+str(n)
        self.ipALLlist =  ipAllList
        self.num = len(self.ipALLlist)    #IP池总数
        self.n = n+1
        self.start()                #以start()方式来启动线程，并运行Run方法

    #重新实现run方法，这样我们就可以通过render给线程传递相关信息  
    def run(self):
        #不会被直接调用
        #实际运行过程:尽可能减少全局变量使用
        n = 0        
        while not self.exiting and n < self.num:   #保证线程可以随时退出和IP池没有扫描完
            HOST = self.ipALLlist[n]
            #print '\t\t[Add]'+str(n)+'\t'+str(self.ipALLlist[n]) 
            
            if self.ircFind(HOST) == True:
                #print 'OK'
                self.emit(SIGNAL("output(bool,QString,int)"),True,HOST[0],HOST[1])
                n += 1
            else:
                #print 'NO'
                self.emit(SIGNAL("output(bool,QString,int)"),False,HOST[0],HOST[1])
                n += 1
        #self.printEmitOK('*_* 恭喜，完成 第%i线程列表所有IP和端口分析  *_* '%(self.n))
        self.finishEmit()
        
        
    def ircFind(self,HOST):
        while True:
            try:
                self.printEmit('    正在请求IP和端口...')
                #step 1 : 初步探测 IRC Server，扫描端口
                #step1.1 创建套接字
                IRCConn = socks.socksocket()    #代理修改
                #step1.2 使用SOCK Proxy代理
                IRCConn.setproxy(SOCK_PROXY_TYPE, SOCK_PROXY_addr, SOCK_PROXY_port, SOCK_PROXY_rdns, SOCK_PROXY_username, SOCK_PROXY_password)
                #step1.3 设置超时时间
                #IRCConn.setblocking(0)  #为非阻塞模式
                IRCConn.settimeout(ConnectTIMEOUT)
                IRCConn.connect(HOST)
            except socket.error,e:
                #没有连接成功
                self.trycnt += 1
                if self.trycnt >= MaxTryNum:
                    #此处需要对返回值和打印进行调整
                    print 'Sorry,now get the max trys!!! Quit now'
                    self.printEmit('Sorry，已经达到最大连接次数，失败')
                    self.trycnt = 0
                    return False
                print '%i 次连接(%s,%s)未成功，稍后重试...'%(self.trycnt,HOST[0],HOST[1])
                tmp = '%i 次连接(%s,%s)未成功，稍后重试...'%(self.trycnt,HOST[0],HOST[1])
                self.printEmit(tmp)
            else:
                print '成功连接(%s,%s),该机器已打开此端口'%(HOST[0],HOST[1])
                tmp = '成功连接(%s,%s),该机器已打开此端口，进行进一步探测...'%(HOST[0],HOST[1])
                self.printEmit(tmp)
                break
        IRCConn.settimeout(LONGTIMEOUT)     #加长返回时间，防止出现timeout现象
        
        #step 2: 随机登陆频道（此处需要进行扩充，获取服务器频道列表，逐一进入）
        IRCConn.send('USER %s %s %s %s \n' % (USERNAME,HOSTNAME,SERVERNAME,REALNAME))
        IRCConn.send('NICK %s \n' % NICKNAME)       #Nick 可能此处需要进行扩展，看是否重名
        IRCConn.send('JOIN %s \n' % CHANNEL)        #加入频道
        
        #step 3: 处理返回信息，进一步
        try:
            flag = True 
            readbuf = ''
            while True:
                buf = IRCConn.recv(RecvSIZE)
                readbuf = readbuf + buf
                print buf

                if flag == True:
                    self.ircTryCnt += 1
                    for line in buf.split('\n'):
                        if line == '':continue
                        line = line.split()
                        if 'PING' in line or 'ping' in line or 'Ping' in line or '/NAMES' in line or 'used' in line or '/MODE' in line or 'Register' in line :
                            flag = False
                            self.printEmit('成功接收PING信号')
                            if len(line) ==1 : IRCConn.send('PONG \n')
                            if len(line) ==2 : IRCConn.send('PONG %s \n' % line[1])
                            return True
                            #break
                            #此处已经表明，此服务器为IRC服务器
                else:
                    #进一步验证,出现‘Welcome to the UnderNet IRC Network’字样
                    if readbuf.find('Welcome to the UnderNet IRC Network') != -1 or readbuf.find('/MOTD')!=-1:
                        #此处已经表明，此服务器为IRC服务器，最终验证
                        print '此服务器为IRC服务器，可以对外提供服务'
                        self.printEmit('此服务器为IRC服务器，可以对外提供服务')
                        self.ircTryCnt = 1
                        break  
                if self.ircTryCnt > irccnt:
                    print 'irc 获取次数过多'
                    self.printEmit('irc 获取次数过多')
                    break
        except socket.error,e:
            print str(e) 
            self.ircTryCnt = 0  #error
                 
        #step 4：返回结果
        if self.ircTryCnt == 1:
            #print 'success'
            return True
        else:
            #print 'failed'
            return False
    
      
