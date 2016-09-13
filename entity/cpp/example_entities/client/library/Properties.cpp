//
// Created by Salomon Lee on 9/13/16.
//

#include <fstream>
#include "Properties.hpp"

Properties::Properties(std::string file_name) {
    init(file_name);

}

void Properties::init(std::string config_file) {
    std::ifstream file;
    file.open(config_file);
    if(file.is_open()) {
        std::string line;
        while(getline(file,line)) {
            std::cout<<line<<std::endl;
        }
    }
}