//
// Created by Salomon Lee on 9/13/16.
//

#ifndef CLIENT_STRUCTURES_HPP
#define CLIENT_STRUCTURES_HPP

#include <iostream>
#include <string>
#include <list>

struct _entityInfo{
    std::string name;
    std::string group;
    std::string private_key_path;
};

struct _authInfo {
    int id;
    std::string host;
    int port;
    std::string public_key_path;
};

struct _targetServerInfo {
    std::string name;
    std::string host;
    int port;
};

typedef _entityInfo EntityInfo;
typedef _authInfo AuthInfo;
typedef std::list<_targetServerInfo> TargetServerInfo;

#endif //CLIENT_STRUCTURES_HPP
