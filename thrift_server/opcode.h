#ifndef __SERVICECOMMONCODE_H__
#define __SERVICECOMMONCODE_H__

namespace CommandCode
{
    const short REQUEST_COMM_REGISTER_LISTENER = 0x0001; //  扩展服务注册监听请求
    const short REQUEST_COMM_UNREGISTER_LISTENER = 0x0002; // 扩展服务取消监听请求
    const short REQUEST_COMM_SUBMIT_DEALED_SKB = 0x0003; //  扩展服务提交处理结果包
    const short REQUEST_COMM_QUERY_BASEPATH = 0x0004; //  查询隧道/通道/辅助通道信息
    const short NOTIFY_COMM_REPORT_LOG = 0x0005; // 提交日志通知
	const short CONF_CLEAR  = 0x0006;    //清空策略
	const short CONF_RELOAD = 0x0007;    //重载
    const short REQUEST_SYSTEM_ID = 0x0008;  //请求系统id

    const short MSG_DOG_STARTALL = 0x1000;
    const short MSG_DOG_STOPALL = 0x1001;
    const short MSG_DOG_LOADLICNESE = 0x1002;
    const short MSG_DOG_SHOWLICNESE = 0x1003;
    const short REQUEST_BASE_SUBMIT_SKB_POSITIVE = 0x2000; //  基础服务转交正向数据包
    const short REQUEST_BASE_SUBMIT_SKB_REVERSE = 0x2001; //  基础服务转交逆向数据包
    const short REQUEST_PING = 0x2002;
    
    const short REQUEST_CFG_PRINT_ALL_CONFIG = 0x2FFF;   //打印内存中数据

	const short REQUEST_CFG_ADD_VP = 0x3000;//WEB向配置服务发起隧道建立请求
	const short REQUEST_CFG_DELETE_VP = 0x3001;//WEB端向配置服务发起隧道销毁请求
	const short REQUEST_CFG_ALTER_VP = 0x3002;//WEB端向配置服务发起隧道修改请求
	const short REQUEST_CFG_QUERY_VP = 0x3003;//配置服务向WEB发起隧道查询

	const short REQUEST_CFG_QUERY_KERNEL_LINK = 0x3010;//WEB、配置服务进行向基础服务查询链路信息
	const short REQUEST_CFG_BLOCK_KERNEL_LINK = 0x3011;//WEB、配置服务进行向基础服务实时链路阻断
	
	const short REQUEST_CFG_QUERY_SYSINFO = 0x3013; //SIP系统信息查询，内存，CPU，磁盘，网口，系统运行时间等。
    const short REQUEST_CFG_REPORT_PROTOCOL = 0x0009; //自动识别协议（资源）上报

    const short REQUEST_ACCOUNT_UNLOCK = 0x3041;

	const short REQUEST_CFG_QUERY_DESEN_RULE_EX = 0x9000;
	const short REQUEST_CFG_QUERY_DESEN_DICT_EX = 0x9001;

	const short REQUEST_CFG_QUERY_MAX_CONNECT_LIMIT_MEMORY_DATA = 0x9002;
};

#endif


