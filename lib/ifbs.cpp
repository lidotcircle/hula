#include "../include/ifbs.h"

#include <stdio.h>


IFBS::IFBS(const std::string& data): m_data(data) {}

bool IFBS::is_boolean() //{
{
    if(this->m_data == "true" || this->m_data == "false") return true;
    return false;
} //}
bool IFBS::is_float() //{
{
    double n;
    size_t len = 0;

    int r = sscanf(this->m_data.c_str(), "%lf %ld", &n, &len);
    return (r == 1 && !this->m_data[len]);
} //}
bool IFBS::is_integer() //{
{
    int n;
    size_t len = 0;

    int r = sscanf(this->m_data.c_str(), "%d %ld", &n, &len);
    return (r == 1 && !this->m_data[len]);
} //}

IFBS::operator int() const {return atoi(this->m_data.c_str());}
IFBS::operator double() const {return atof(this->m_data.c_str());}
IFBS::operator bool() const {return this->m_data == "true" ? true : false;}
IFBS::operator const std::string&() const {return this->m_data;}

