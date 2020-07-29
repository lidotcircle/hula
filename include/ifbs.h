#pragma once

#include <string>

class IFBS {
    private:
        std::string m_data;

    public:
        IFBS(const std::string& data);

        bool is_integer();
        bool is_float();
        bool is_boolean();

        operator const std::string&() const;
        operator int() const;
        operator double() const;
        operator bool() const;
};

