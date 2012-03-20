#!/bin/sh
#author:tianweidut
#email:liutianweidlut@qq.com
echo 'IRC 探测 V1.1'
echo '-----------------------------'
echo '----------1.环境安装-----------'
echo '-----------------------------'
#权限提升
#安装python 2.6
echo '1.1 python 编程环境验证与安装...'
sudo apt-get install python2.6-dev -y >> log.log
#安装qt
echo '1.2 QT 编程环境验证与安装...'
sudo apt-get install libqt4-dev libqt4-gui qt4-dev-tools qt4-qtconfig -y >> log.log
#安装pyqt
echo '1.3 pyQT 编程环境验证与安装...'
sudo apt-get install "python-qt4-*" -y >> log.log
#安装nmap
echo '1.4 nmap 编程环境验证与安装...'
sudo apt-get install nmap -y >> log.log
echo '\t[调试信息] 软件安装信息参见log.log文件'

echo '-----------------------------'
echo '----------2.运行程序-----------'
echo '-----------------------------'
sudo rm tianwei.xml
sudo python MultiIRCFound.py
echo '-----------------------------'
echo '----------3.结果分析-----------'
echo '-----------------------------'
gedit  iprecord.txt >> log.log
echo '*_* 程序运行完成 *_*'
