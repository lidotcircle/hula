#pragma once

#include "file.h"
#include "object_manager.h"

#include <stack>


class ConfigFile: virtual protected FileAbstraction, public CallbackManager //{
{
    public:
        using LoadCallback  = void (*)(int status, void*);
        using WriteCallback = void (*)(int status, void*);


    private:
        std::stack<std::string> m_error;

        static void open_callback(int status, void* data);
        static void read_callback(ROBuf buf, int status, void* data);
        static void seek_callback(int status, void* data);
        static void close_callback(int status, void* data);
        static void write_callback(ROBuf buf, int staus, void* data);

        static void open_callback_for_write(int status, void* data);
        static void truncate_callback_for_write(int status, void* data);


    protected:
        virtual bool  fromROBuf(ROBuf buf) = 0;
        virtual ROBuf toROBuf() = 0;

        void setError(const std::string& error);
        void clearError();

    public:
        bool loadFromFile(LoadCallback cb, void* data);
        bool writeToFile(WriteCallback cb, void* data);
        inline const auto& getError() {return this->m_error;}
}; //}

