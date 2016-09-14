//
// Created by Salomon Lee on 9/13/16.
//

#ifndef CLIENT_STRUCTURES_HPP
#define CLIENT_STRUCTURES_HPP

#include <iostream>
#include <string>
#include <list>

#define EI_NAME 0
#define EI_GROUP 1
#define EI_PK_PATH 2

#define AI_ID 10
#define AI_HOST 11
#define AI_PORT 12
#define AI_PK_PATH 13

#define SI_QTY 20
#define SI_NAME 21
#define SI_HOST 22
#define SI_PORT 23

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
typedef _targetServerInfo TargetServerInfo;

#endif //CLIENT_STRUCTURES_HPP
