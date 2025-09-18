#include <thrift/server/TThreadPoolServer.h>
#include "ThriftServer.h"

ThriftServer::ThriftServer(MessageServiceIf *pService, int iPort, int iThreadnum)
{
	boost::shared_ptr<MessageServiceIf> handler(pService);
    boost::shared_ptr<TProcessor> processor(new MessageServiceProcessor(handler));
    boost::shared_ptr<TServerTransport> serverTransport(new TServerSocket(iPort));
    boost::shared_ptr<TTransportFactory> transportFactory(new TFramedTransportFactory());
    boost::shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());
    m_processor = processor;
    m_serverTransport = serverTransport;
    m_transportFactory = transportFactory;
    m_protocolFactory = protocolFactory;
    m_iThreadNum = iThreadnum;
    m_iPort = iPort;
}

ThriftServer::~ThriftServer() {
}

boost::shared_ptr<TServer> ThriftServer::GetServer() const
{
    return m_server;
}

int ThriftServer::Start()
{
    m_threadManager = ThreadManager::newSimpleThreadManager(m_iThreadNum);
    boost::shared_ptr<PosixThreadFactory> threadFactory = boost::shared_ptr<PosixThreadFactory>(new PosixThreadFactory());
    m_threadManager->threadFactory(threadFactory);
    m_threadManager->start();

    TServer *pServer = new TThreadPoolServer(m_processor,
        m_serverTransport,
        m_transportFactory,
        m_protocolFactory,
        m_threadManager);
    
    boost::shared_ptr<TServer> serve(pServer);
    m_server = serve;
    pthread_t tid;
	int nRet = pthread_create(&tid, NULL, StartAction, this);
	return nRet!=0 ? -1:0;
}

void *ThriftServer::StartAction(void* arg)
{
    pthread_detach(pthread_self());
    ThriftServer* pThriftServer = (ThriftServer*)arg;
    boost::shared_ptr<TServer> server(pThriftServer->GetServer());
    try {
    	server->serve();
    }
    catch (const std::exception&) {
        return NULL;
    }
	
    return NULL;
}

