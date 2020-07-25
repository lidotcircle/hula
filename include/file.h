#pragma once

#include "robuf.h"

#include <string>
#include <memory>


/** file abstraction */

struct Stat {
    uint64_t st_dev;
    uint64_t st_mode;
    uint64_t st_nlink;
    uint64_t st_uid;
    uint64_t st_gid;
    uint64_t st_rdev;
    uint64_t st_ino;
    uint64_t st_size;
    uint64_t st_blksize;
    uint64_t st_blocks;
    uint64_t st_flags;
    uint64_t st_gen;
    time_t   st_atim;
    time_t   st_mtim;
    time_t   st_ctim;
    time_t   st_birthtim;
};


enum FileMechanismType {LIBUV};
struct __FileMechanism {
    virtual FileMechanismType getType() = 0;
    inline virtual ~__FileMechanism() {}
};


class FileAbstraction //{
{
    public:
        using OpenCallback     = void (*)(int status, void* data);
        using CloseCallback    = void (*)(int status, void* data);
        using ReadCallback     = void (*)(ROBuf buf, int status, void* data);
        using WriteCallback    = void (*)(ROBuf buf, int status, void* data);
        using SeekCallback     = void (*)(int status, void* data);
        using StatCallback     = void (*)(std::shared_ptr<Stat> stat, int status, void* data);
        using TruncateCallback = void (*)(int status, void* data);

        using FileEventType = enum {RENAME, CHANGE};
        using FileMechanism = std::shared_ptr<__FileMechanism>;


    protected:
        inline virtual void fileEventRaise(const std::string& filename, FileEventType) {}


    public:
        virtual bool open(int flags, int mode = 0666, OpenCallback cb = nullptr, void* data = nullptr) = 0;
        virtual bool close(CloseCallback cb = nullptr, void* data = nullptr) = 0;
        virtual ROBuf  read(size_t n, ReadCallback cb = nullptr, void* data = nullptr) = 0;
        virtual ROBuf  read(size_t start, size_t len, ReadCallback cb = nullptr, void* data = nullptr) = 0;
        virtual ROBuf  readremain(ReadCallback cb = nullptr, void* data = nullptr) = 0;
        virtual size_t write(ROBuf buf, WriteCallback cb = nullptr, void* data = nullptr) = 0;

        enum SeekType {START = 0, CURRENT, LASTCHAR, END};
        virtual bool seek(int offset, SeekType type = SeekType::START, SeekCallback cb = nullptr, void* data = nullptr) = 0;

        virtual std::shared_ptr<Stat> stat(StatCallback cb, void* data) = 0;

        virtual bool reopen(const std::string& filename, int flags, int mode, OpenCallback cb = nullptr, void* data = nullptr) = 0;
        virtual const std::string& filename() = 0;

        virtual bool truncate(size_t size, TruncateCallback cb, void* data) = 0;

        virtual bool opened() = 0;
        virtual bool error() = 0;
        virtual int  flags() = 0;
        virtual int  mode() = 0;

        virtual FileMechanism GetFileMechanism() = 0;

        virtual inline ~FileAbstraction() {};
}; //}

