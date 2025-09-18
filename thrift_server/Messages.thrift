#!/usr/local/bin/thrift --gen java:beans,hashcode -O ../
#//thrift -r --gen cpp Messages.thrift
#thrift -r --gen java Messages.thrift

struct ResultInfo{
 1:i32   	iCode,
 2:string 	strValue,
}


struct ReqInfo{
 1:i32   	iCode,
 2:string 	strValue
}

struct PortInfo 
{
	1:i32	iVPPort,//隧道端口
	2:i32	iVCPort	 //通道端口
}

enum ESkbType {
    UNKNOW = 0, //未知　
    ORGIN_TYPE = 1, //原始包
    SPLITE = 2,  //拆分包  　　
    MERGE = 3,   //合并包
    MODIFY = 4, //修改包
    DROP = 5,   //丢弃包
    REVERSE     //源端信息目的端信息翻转
}

struct  BaseHead
{
	1:i32 iSeq,	 	     //包序号，填0
	2:i32 iTotal,		 //总包数，填0
	3:list<i64> lstGuid, //list 合并包时，需要所有包的guid OperType为3是有有效
	4:i64 iGuid,         //当前包的guid    
	5:ESkbType OperType  //数据包处理方式0： 1：  2：  3： 4：5
}


struct BaseSKB{
	1:i32 iCode,
    2:PortInfo   portInfo,
    3:BaseHead  head,//基础服务封装的包头
    4:string strSKB	//SKB数据包
}

service MessageService { 
  //json 格式请求接口
  oneway void SendMessage(1:ReqInfo msg),
  ResultInfo SendAndRecMessage(1:ReqInfo msg), 
  //基础服务，扩展服务数据包交换接口
  oneway void SendPacket(1:BaseSKB msg),
  ResultInfo SendAndRecPacket(1:BaseSKB msg)
}