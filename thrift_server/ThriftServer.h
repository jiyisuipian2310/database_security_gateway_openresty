#ifndef __THRIFT_SERVER_H__
#define __THRIFT_SERVER_H__

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/server/TThreadPoolServer.h>
#include <thrift/server/TNonblockingServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/concurrency/ThreadManager.h>
#include <thrift/concurrency/PosixThreadFactory.h>
#include "MessageService.h"

using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;
using namespace ::apache::thrift::concurrency;

class ThriftServer {
public:
    ThriftServer(MessageServiceIf *pService, int port, int threadnum = 1);
    virtual ~ThriftServer();
    
    int Start(); //服务启动
    int Stop(); //服务停止

	boost::shared_ptr<TServer> GetServer() const;

private:
    static void* StartAction(void* arg);

private:
    boost::shared_ptr<MessageServiceIf> m_handler;
    boost::shared_ptr<TServer> m_server;
    boost::shared_ptr<TProcessor> m_processor;
    boost::shared_ptr<TServerTransport> m_serverTransport;
    boost::shared_ptr<TTransportFactory> m_transportFactory;
    boost::shared_ptr<TProtocolFactory> m_protocolFactory;
    boost::shared_ptr <ThreadManager> m_threadManager;
    int m_iThreadNum;
    int m_iPort;
};

#endif