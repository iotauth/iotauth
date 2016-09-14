//
// Created by Salomon Lee on 9/13/16.
//

#ifndef CLIENT_PROPERTIES_HPP
#define CLIENT_PROPERTIES_HPP

#include "Structures.hpp"

class Properties {
private:
    EntityInfo entityInfo;
    AuthInfo authInfo;
    std::list<TargetServerInfo> targetServerInfoList;
    void init(std::string config_file);
    int getKeyValue(std::string key);
protected:
    void addTargetServerInfo(_targetServerInfo serverInfo);
public:
    Properties(std::string file_name);
    EntityInfo getEntityInfo();
    AuthInfo getAuthInfo();
    std::list<TargetServerInfo> getTargetServerInfo();
    virtual ~Properties(){};
};


#endif //CLIENT_PROPERTIES_HPP
