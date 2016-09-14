//
// Created by Salomon Lee on 9/13/16.
//

#include <fstream>
#include <sstream>
#include "Properties.hpp"

extern const std::string __EI_NAME = "entityInfo.name";
extern const std::string __EI_GROUP = "entityInfo.group";
extern const std::string __EI_PK_PATH = "entityInfo.private.key.path";
extern const std::string __AI_ID = "authInfo.id";
extern const std::string __AI_HOST = "authInfo.host";
extern const std::string __AI_PORT = "authInfo.port";
extern const std::string __AI_PK_PATH = "authInfo.private.key.path";
extern const std::string __SI_QTY = "targetServerInfo.server.qty";
extern const std::string __SI_NAME = "targetServerInfo.name";
extern const std::string __SI_HOST = "targetServerInfo.host";
extern const std::string __SI_PORT = "targetServerInfo.port";

Properties::Properties(std::string file_name) {
    init(file_name);

}

int Properties::getKeyValue(std::string key) {
    if (key.compare(__EI_NAME) == 0) return EI_NAME;
    else if (key.compare(__EI_GROUP) == 0) return EI_GROUP;
    else if (key.compare(__EI_PK_PATH) == 0) return EI_PK_PATH;
    else if (key.compare(__AI_ID) == 0) return AI_ID;
    else if (key.compare(__AI_HOST) == 0) return AI_HOST;
    else if (key.compare(__AI_PORT) == 0) return AI_PORT;
    else if (key.compare(__AI_PK_PATH) == 0) return AI_PK_PATH;
    else if (key.compare(__SI_QTY) == 0) return SI_QTY;
    else if (key.compare(0, __SI_NAME.size(), __SI_NAME) == 0) return SI_NAME;
    else if (key.compare(0, __SI_HOST.size(), __SI_HOST) == 0) return SI_HOST;
    else if (key.compare(0, __SI_PORT.size(), __SI_PORT) == 0) return SI_PORT;
    else return -1;
}

void Properties::addTargetServerInfo(_targetServerInfo serverInfo) {
    targetServerInfoList.push_back(serverInfo);
}

void Properties::init(std::string config_file) {
    std::ifstream file;
    file.open(config_file);
    if(file.is_open()) {
        std::string line;
        _targetServerInfo serverInfo;
        while(getline(file,line)) {
            std::stringstream tokenizer(line);
            std::string token;
            while (getline(tokenizer, token, '=')) {
                switch (getKeyValue(token)){
                    case EI_NAME:
                        getline(tokenizer, token, '=');
                        entityInfo.name = token;
                        break;
                    case EI_GROUP:
                        getline(tokenizer, token, '=');
                        entityInfo.group = token;
                        break;
                    case EI_PK_PATH:
                        getline(tokenizer, token, '=');
                        entityInfo.private_key_path = token;
                        break;
                    case AI_ID:
                        getline(tokenizer, token, '=');
                        authInfo.id = std::stoi(token);
                        break;
                    case AI_HOST:
                        getline(tokenizer, token, '=');
                        authInfo.host = token;
                        break;
                    case AI_PORT:
                        getline(tokenizer, token, '=');
                        authInfo.port = std::stoi(token);
                        break;
                    case AI_PK_PATH:
                        getline(tokenizer, token, '=');
                        authInfo.public_key_path = token;
                        break;
                    case SI_NAME:
                        getline(tokenizer, token, '=');
                        serverInfo.name = token;
                        break;
                    case SI_HOST:
                        getline(tokenizer, token, '=');
                        serverInfo.host = token;
                        break;
                    case SI_PORT:
                        getline(tokenizer, token, '=');
                        serverInfo.port = std::stoi(token);
                        addTargetServerInfo(serverInfo);
                        break;
                    default:
                        break;
                }
            }
        }
    }
}

EntityInfo Properties::getEntityInfo() {
    return entityInfo;
}

AuthInfo Properties::getAuthInfo() {
    return authInfo;
}

std::list<TargetServerInfo> Properties::getTargetServerInfo(){
    return targetServerInfoList;
}