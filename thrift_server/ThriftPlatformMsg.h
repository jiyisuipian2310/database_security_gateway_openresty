#ifndef __MESSAGESERVICEHANDLER_H__
#define __MESSAGESERVICEHANDLER_H__

#include <string>
#include "MessageService.h"

using namespace std;

class ThriftPlatformMsg:public MessageServiceIf
{
public:
    virtual ~ThriftPlatformMsg();
    ThriftPlatformMsg();

    virtual void SendMessage(const ReqInfo& msg);

    virtual void SendAndRecMessage(ResultInfo& _return, const ReqInfo& msg);

    virtual void SendPacket(const BaseSKB& msg);

    virtual void SendAndRecPacket(ResultInfo& _return, const BaseSKB& msg);
};
#endif /* __MESSAGESERVICEHANDLER_H__ */
