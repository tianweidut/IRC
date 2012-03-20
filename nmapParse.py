#!/usr/bin/env python
# -*- coding:utf-8 -*-
'''
Created on 2011-6-23

@author: tianwei

func:
'''
import sys,string,time,struct,os
from PyQt4.QtCore import *
from PyQt4.QtGui import *

NMAP_FILENAME = 'tianwei.xml'

class NmapParse(QThread):               #使用PyQt中的线程代替Python本身的线程       
    def __init__(self,parent=None):
        QThread.__init__(self,parent)
        self.ipString = '127.0.0.1'
        self.cmd = ''
        
    #当work线程对象在被销毁的时候，需要停止线程
    def __del__(self):
        self.wait()      
                  
    def render(self,ip):
        self.ipString = ip
        self.start()                #以start()方式来启动线程，并运行Run方法

    def printEmitOK(self,str):
        #打印发射信号
        str = unicode('\t[Finished]','utf-8') + unicode(str,'utf-8')
        self.emit(SIGNAL("debugPrintOK(QString)"),str)
        
        
    #重新实现run方法，这样我们就可以通过render给线程传递相关信息  
    def run(self):
        #不会被直接调用
        #step1 : 生成命令行
        self.cmd = 'nmap -sS ' + self.ipString + ' -oX ' + NMAP_FILENAME
        print '!!!!:' + self.cmd
        rst = os.system(self.cmd)
        if rst != 0:
            self.printEmitOK('Error!!! require root privileges')
            return 
            
        #实际运行过程:尽可能减少全局变量使用
        #self.printEmitOK('*_* The thread finished the work!')   

