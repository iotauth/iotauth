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
    TargetServerInfo targetServerInfo;
    void init(std::string config_file);
protected:
    void setEntityInfo(std::string name, std::string group, std::string private_key_path);
    void setAuthInfo(int id, std::string host, int port, std::string private_key_path);
    void addTargetServerInfo(std::string name, std::string host, int port);
public:
    Properties(std::string file_name);
    EntityInfo getEntityInfo();
    AuthInfo getAuthInfo();
    TargetServerInfo getTargetServerInfo();
    virtual ~Properties(){};
};


#endif //CLIENT_PROPERTIES_HPP
