#pragma once

#include "file.h"
#include "object_manager.h"

#include <uv.h>


struct __UVFileMechanism: public __FileMechanism {
    uv_loop_t* m_loop;
    __UVFileMechanism(uv_loop_t* loop) {this->m_loop = loop;}
    inline FileMechanismType getType() {return FileMechanismType::LIBUV;}
};


class UVFile: virtual public FileAbstraction, protected CallbackManager //{
{
    private:
        std::string m_filename;
        uint32_t m_flags;
        uint32_t m_mode;

        int m_fd;
        bool m_error;
        bool m_close_error;
        size_t m_pos;

        uv_loop_t* mp_loop;

        uv_fs_event_t* m_file_watcher;

        static void open_callback(uv_fs_t* req);
        static void close_callback(uv_fs_t* req);
        static void read_callback(uv_fs_t* req);
        static void write_callback(uv_fs_t* req);
        static void stat_callback(uv_fs_t* req);
        static void stat_callback_for_readall(std::shared_ptr<Stat>, int, void*);
        static void stat_callback_for_seek(std::shared_ptr<Stat>, int, void*);
        static void truncate_callback(uv_fs_t* req);

        ROBuf __read(size_t n, ReadCallback cb, void* data);
        bool  setoffset(int offset, SeekType type, size_t filesize);

        void register_file_watcher();
        void release_file_watcher();
        static void file_watcher_callback(uv_fs_event_t* handle, const char* filename, int event, int status);

    public:
        UVFile(uv_loop_t* loop, const std::string& filename);
        bool open(int flags, int mode = 0666, OpenCallback cb = nullptr, void* data = nullptr) override;
        bool close(CloseCallback cb = nullptr, void* data = nullptr) override;
        ROBuf  read(size_t n, ReadCallback cb = nullptr, void* data = nullptr) override;
        ROBuf  read(size_t start, size_t len, ReadCallback cb = nullptr, void* data = nullptr) override;
        ROBuf  readremain(ReadCallback cb = nullptr, void* data = nullptr) override;
        size_t write(ROBuf buf, WriteCallback cb = nullptr, void* data = nullptr) override;

        bool seek(int offset, SeekType type = SeekType::START, SeekCallback cb = nullptr, void* data = nullptr) override;
        std::shared_ptr<Stat> stat(StatCallback cb, void* data) override;

        bool truncate(size_t size, TruncateCallback cb, void* data) override;

        bool reopen(const std::string& filename, int flag = 0, int mode = 0, OpenCallback cb = nullptr, void* data = nullptr) override;
        const std::string& filename() override;

        bool opened() override;
        bool error()  override;
        int  flags()  override;
        int  mode()   override;

        FileMechanism GetFileMechanism() override;
        static FileMechanism loop_to_FileMechanism(uv_loop_t* loop);

        inline auto get_uv_loop() {return this->mp_loop;}
        ~UVFile();
}; //}

