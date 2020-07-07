#include "../include/file_libuv.h"
#include "../include/libuv_utils.h"

#include <assert.h>

#include <memory>


struct uvfile_state: public CallbackPointer {
    UVFile* _this;
    void*   _cb;
    void*   _data;
    inline uvfile_state(UVFile* f, void* cb, void* data): _this(f), _cb(cb), _data(data) {}
};

static void uv_stat_to_stat(uv_stat_t* uv_stat, Stat* stat) //{
{
    stat->st_dev      = uv_stat->st_dev;
    stat->st_mode     = uv_stat->st_mode;
    stat->st_nlink    = uv_stat->st_nlink;
    stat->st_uid      = uv_stat->st_uid;
    stat->st_gid      = uv_stat->st_gid;
    stat->st_rdev     = uv_stat->st_rdev;
    stat->st_ino      = uv_stat->st_ino;
    stat->st_size     = uv_stat->st_size;
    stat->st_blksize  = uv_stat->st_blksize;
    stat->st_blocks   = uv_stat->st_blocks;
    stat->st_flags    = uv_stat->st_flags;
    stat->st_gen      = uv_stat->st_gen;
    stat->st_atim     = uv_stat->st_atim.tv_nsec; // FIXME
    stat->st_mtim     = uv_stat->st_mtim.tv_nsec;
    stat->st_ctim     = uv_stat->st_ctim.tv_nsec;
    stat->st_birthtim = uv_stat->st_birthtim.tv_nsec;
} //}

static void free_uv_fs_t(uv_fs_t* req) {uv_fs_req_cleanup(req); delete req;}
#define freereq(req) free_uv_fs_t(req); req = nullptr;
#define CAST_OUT_DATA(cbtype) \
    std::shared_ptr<uv_fs_t> req(p_req, free_uv_fs_t); \
    uvfile_state* msg = \
    dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(uv_req_get_data((uv_req_t*)p_req))); \
    assert(msg); \
    uv_req_set_data((uv_req_t*)p_req, nullptr); \
    auto   _this = msg->_this; \
    cbtype _cb   = reinterpret_cast<decltype(_cb)>(msg->_cb); \
    auto   _data = msg->_data; \
    auto   run   = msg->CanRun(); \
    delete msg;


UVFile::UVFile(uv_loop_t* loop, const std::string& filename): m_filename(filename) //{
{
    this->mp_loop = loop;

    this->m_flags = 0;
    this->m_mode = 0;
    this->m_fd = -1;
    this->m_error = false;
    this->m_close_error = false;

    this->m_pos = 0;

    this->m_watching = false;
    this->m_file_watcher = nullptr;
    this->register_file_watcher();
    this->m_watching = true;
} //}

void UVFile::register_file_watcher() //{
{
    assert(this->m_file_watcher == nullptr);
    this->m_file_watcher = new uv_fs_event_t();
    uv_fs_event_init(this->mp_loop, this->m_file_watcher);
    uv_handle_set_data((uv_handle_t*)this->m_file_watcher, this);
    uv_fs_event_start(this->m_file_watcher, file_watcher_callback, this->m_filename.c_str(), 0);
} //}
void UVFile::release_file_watcher() //{
{
    uv_fs_event_stop(this->m_file_watcher);
    uv_close((uv_handle_t*)this->m_file_watcher, UVU::delete_closed_handle<decltype(this->m_file_watcher)>);
    this->m_file_watcher = nullptr;
} //}
/** [static] */
void UVFile::file_watcher_callback(uv_fs_event_t* handle, const char* filename, int event, int status) //{
{
    UVFile* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*)handle));

    if(status < 0) {
        /*
        _this->release_file_watcher(); // TODO
        _this->m_watching = false;
        */
        return;
    }

    if(_this->m_error) {
        _this->release_file_watcher();
        _this->m_watching = false;
        return;
    }

    switch(event) {
        case uv_fs_event::UV_RENAME:
            _this->fileEventRaise(filename, FileEventType::RENAME);
            break;
        case uv_fs_event::UV_CHANGE:
            _this->fileEventRaise(filename, FileEventType::CHANGE);
            break;
    }
} //}

bool UVFile::open(int flags, int mode, OpenCallback cb, void* data) //{
{
    assert(this->m_error == false);
    assert(this->m_fd == -1);
    this->m_flags = flags;
    this->m_mode  = mode;

    uv_fs_t* req = new uv_fs_t();

    if(cb == nullptr) {
        assert(data == nullptr);
        auto rv = uv_fs_open(this->mp_loop, req, this->filename().c_str(), this->m_flags, this->m_mode, nullptr);
        if(rv < 0)
            this->m_error = true;
        else
            this->m_fd = rv;
        freereq(req);
        return (this->m_fd > 0);
    }

    auto ptr = new uvfile_state(this, (void*)cb, data);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->add_callback(ptr);

    uv_fs_open(this->mp_loop, req, this->filename().c_str(), this->m_flags, this->m_mode, UVFile::open_callback);
    return true;
} //}
/** [static] */
void UVFile::open_callback(uv_fs_t* p_req) //{
{
    CAST_OUT_DATA(OpenCallback);
    assert(uv_fs_get_type(req.get()) == uv_fs_type::UV_FS_OPEN);

    if(!run) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(req->result < 0) {
        _this->m_error = true;
        _this->m_fd = -1;
        _cb(-1, _data);
    } else {
        _this->m_fd = req->result;
        _cb(0, _data);
    }
} //}

bool UVFile::close(CloseCallback cb, void* data) //{
{
    assert(this->m_fd > 0);
    assert(this->m_close_error == false);

    uv_fs_t* req = new uv_fs_t();

    if(cb == nullptr) {
        assert(data == nullptr);
        auto rv = uv_fs_close(this->mp_loop, req, this->m_fd, nullptr);
        this->m_fd = -1;
        if(rv < 0) {
            this->m_error = true;
            this->m_close_error = true;
        }
        freereq(req);
        return !this->m_close_error;
    }

    auto ptr = new uvfile_state(this, (void*)cb, data);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->add_callback(ptr);

    uv_fs_close(this->mp_loop, req, this->m_fd, close_callback);
    return true;
} //}
/** [static] */
void UVFile::close_callback(uv_fs_t* p_req) //{
{
    CAST_OUT_DATA(CloseCallback);
    assert(uv_fs_get_type(req.get()) == uv_fs_type::UV_FS_CLOSE);
    
    if(!run) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(req->result < 0) {
        _this->m_error = true;
        _this->m_close_error = true;
        _cb(-1, _data);
    } else {
        _cb(0, _data);
    }
} //}

struct uvfile_read_state: public uvfile_state {
    uv_buf_t* _uvbuf;
    inline uvfile_read_state(UVFile* _this, void* cb, void* data, uv_buf_t* buf):
        uvfile_state(_this, cb, data), _uvbuf(buf) {}
};
ROBuf UVFile::__read(size_t n, ReadCallback cb, void *data) //{
{
    assert(this->m_fd > 0);
    assert(this->m_error == false);
    assert(n > 0);

    uv_fs_t* req = new uv_fs_t();

    uv_buf_t* buf = new uv_buf_t();
    buf->base = (char*)malloc(n);
    buf->len  = n;

    if(cb == nullptr) {
        assert(data == nullptr);
        auto rv = uv_fs_read(this->mp_loop, req, this->m_fd, buf, 1, this->m_pos, nullptr);
        if(rv < 0)
            this->m_error = true;

        ROBuf retbuf(buf->base, rv < 0 ? n : rv, 0, free);
        freereq(req);
        delete buf;

        if(this->m_error) {
            return ROBuf();
        } else {
            this->m_pos += rv;
            return retbuf;
        }
    }

    auto ptr = new uvfile_read_state(this, (void*)cb, data, buf);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->add_callback(ptr);

    uv_fs_read(this->mp_loop, req, this->m_fd, buf, 1, this->m_pos, read_callback);
    return ROBuf();
} //}
/** [static] */
void UVFile::read_callback(uv_fs_t* p_req) //{
{
    uvfile_read_state* _msg =
    dynamic_cast<decltype(_msg)>(static_cast<CallbackPointer*>(uv_req_get_data((uv_req_t*)p_req)));
    assert(_msg);
    auto buf = _msg->_uvbuf;
 
    CAST_OUT_DATA(ReadCallback);
    assert(uv_fs_get_type(req.get()) == uv_fs_type::UV_FS_READ);

    ROBuf res(buf->base, req->result < 0 ? buf->len : req->result, 0, free);
    delete buf;
    if(!run) {
        _cb(ROBuf(), -1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(req->result < 0) {
        _this->m_error = true;
        _cb(res, -1, _data);
    } else {
        _cb(res, 0, _data);
    }
} //}

ROBuf UVFile::read(size_t n, ReadCallback cb, void *data) //{
{
    return this->__read(n, cb, data);
} //}
/** [static] */
void UVFile::stat_callback_for_readall(std::shared_ptr<Stat> stat, int status, void* data) //{
{
    uvfile_state* msg =
    dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);
    auto   _this = msg->_this;
    UVFile::ReadCallback _cb   = reinterpret_cast<decltype(_cb)>(msg->_cb);
    auto   _data = msg->_data;
    auto   run   = msg->CanRun();
    delete msg;

    if(!run || status < 0) {
        _cb(ROBuf(), -1, _data);
        return;
    }
    _this->remove_callback(msg);

    assert(stat && "what ???");

    if(stat->st_size == _this->m_pos) {
        _cb(ROBuf(), 0, _data);
        return;
    } else if (stat->st_size < _this->m_pos) {
        _this->m_error = true;
        _cb(ROBuf(), -1, _data);
        return;
    }
    _this->__read(stat->st_size - _this->m_pos, _cb, _data);
} //}
ROBuf UVFile::readremain(ReadCallback cb, void* data) //{
{
    if(cb == nullptr) {
        assert(data == nullptr);
        auto stat = this->stat(nullptr, nullptr);
        if(!stat) return ROBuf();

        if(stat->st_size == this->m_pos) {return ROBuf();}
        if(stat->st_size <  this->m_pos) {
            this->m_error = true;
            return ROBuf();
        }
        return this->__read(stat->st_size - this->m_pos, nullptr, nullptr);
    }

    auto ptr = new uvfile_state(this, reinterpret_cast<void*>(cb), data);
    this->add_callback(ptr);
    this->stat(stat_callback_for_readall, ptr);

    return ROBuf();
} //}

std::shared_ptr<Stat> UVFile::stat(StatCallback cb, void* data) //{
{
    assert(this->m_fd > 0);
    assert(this->m_error == false);

    uv_fs_t* req = new uv_fs_t();

    if(cb == nullptr) {
        assert(data == nullptr);
        std::shared_ptr<Stat> stat(nullptr);
        auto rv = uv_fs_fstat(this->mp_loop, req, this->m_fd, nullptr);
        if(rv < 0) {
            this->m_error = true;
        } else {
            stat = std::make_shared<Stat>();
            uv_stat_to_stat(uv_fs_get_statbuf(req), stat.get());
        }
        freereq(req);
        return stat;
    }

    auto ptr = new uvfile_state(this, (void*)cb, data);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->add_callback(ptr);

    uv_fs_fstat(this->mp_loop, req, this->m_fd, stat_callback);
    return std::shared_ptr<Stat>(nullptr);
} //}
/** [static] */
void UVFile::stat_callback(uv_fs_t* p_req) //{
{
    CAST_OUT_DATA(StatCallback);
    assert(uv_fs_get_type(req.get()) == uv_fs_type::UV_FS_FSTAT);
    
    if(!run) {
        _cb(std::shared_ptr<Stat>(nullptr), -1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(req->result < 0) {
        _this->m_error = true;
        _cb(std::shared_ptr<Stat>(nullptr), -1, _data);
    } else {
        std::shared_ptr<Stat> stat(new Stat());
        uv_stat_to_stat(uv_fs_get_statbuf(req.get()), stat.get());
        _cb(stat, 0, _data);
    }
} //}

struct uvfile_write_state: public uvfile_state {
    uv_buf_t* _uvbuf;
    ROBuf*    _buf;
    inline uvfile_write_state(UVFile* _this, void* cb, void* data, uv_buf_t* buf, ROBuf* rbuf):
        uvfile_state(_this, cb, data), _uvbuf(buf), _buf(rbuf) {}
};
size_t UVFile::write(ROBuf wbuf, WriteCallback cb, void *data) //{
{
    assert(this->m_fd > 0);
    assert(this->m_error == false);
    assert(wbuf.size() > 0);

    uv_fs_t* req = new uv_fs_t();

    uv_buf_t* buf = new uv_buf_t();
    buf->base = wbuf.__base();
    buf->len  = wbuf.size();

    if(cb == nullptr) {
        assert(data == nullptr);
        auto rv = uv_fs_write(this->mp_loop, req, this->m_fd, buf, 1, this->m_pos, nullptr);
        if(rv < 0 || rv != wbuf.size())
            this->m_error = true;

        freereq(req);
        delete buf;

        if(this->m_error) {
            return 0;
        } else {
            this->m_pos += rv;
            return rv;
        }
    }

    auto ptr = new uvfile_write_state(this, (void*)cb, data, buf, new ROBuf(wbuf));
    uv_req_set_data((uv_req_t*)req, ptr);
    this->add_callback(ptr);

    uv_fs_write(this->mp_loop, req, this->m_fd, buf, 1, this->m_pos, write_callback);
 
    return 0;
} //}
/** [static] */
void UVFile::write_callback(uv_fs_t* p_req) //{
{
    uvfile_write_state* _msg =
    dynamic_cast<decltype(_msg)>(static_cast<CallbackPointer*>(uv_req_get_data((uv_req_t*)p_req)));
    assert(_msg);
    auto buf  = _msg->_uvbuf;
    auto rbuf = _msg->_buf;
    ROBuf res(*rbuf);
    delete buf;
    delete rbuf;
 
    CAST_OUT_DATA(ReadCallback);
    assert(uv_fs_get_type(req.get()) == uv_fs_type::UV_FS_WRITE);

    if(!run) {
        _cb(ROBuf(), -1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(req->result < 0) {
        _this->m_error = true;
        _cb(res, -1, _data);
    } else {
        _cb(res, 0, _data);
    }
} //}

bool UVFile::setoffset(int offset, SeekType type, size_t fsize) //{
{
    switch(type) {
        case START:
            if(offset < 0)
                this->m_pos = fsize + 1;
            else
                this->m_pos = offset;
            break;
        case CURRENT:
            if(offset < 0 && (-offset > this->m_pos))
                this->m_pos = fsize + 1;
            else
                this->m_pos += offset;
            break;
        case LASTCHAR:
            if(fsize <= offset)
                this->m_pos = fsize + 1;
            else
                this->m_pos = fsize - offset - 1;
            break;
        case END:
            if(fsize < offset)
                this->m_pos = fsize + 1;
            else
                this->m_pos = fsize - offset;
            break;
    }

    if(this->m_pos > fsize) {
        this->m_error = true;
        return false;
    }
    return true;
} //}
struct uvfile_seek_state: public uvfile_state {
    int _offset;
    UVFile::SeekType _type;
    inline uvfile_seek_state(UVFile* _this, void* cb, void* data, int offset, UVFile::SeekType type):
        uvfile_state(_this, cb, data), _offset(offset), _type(type) {}
};
bool UVFile::seek(int offset, SeekType type, SeekCallback cb, void* data) //{
{
    assert(this->m_fd > 0);
    assert(this->m_error == false);

    if(cb == nullptr) {
        assert(data == nullptr);
        auto stat = this->stat(nullptr, nullptr);
        if(!stat) return false;

        return this->setoffset(offset, type, stat->st_size);
    }

    auto ptr = new uvfile_seek_state(this, reinterpret_cast<void*>(cb), data, offset, type);
    this->add_callback(ptr);
    this->stat(stat_callback_for_seek, ptr);

    return true;
} //}
/** [static] */
void UVFile::stat_callback_for_seek(std::shared_ptr<Stat> stat, int status, void* data) //{
{
    uvfile_seek_state* msg =
    dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);
    auto   _this   = msg->_this;
    UVFile::SeekCallback _cb = reinterpret_cast<decltype(_cb)>(msg->_cb);
    auto   _data   = msg->_data;
    auto   offset  = msg->_offset;
    auto   type    = msg->_type;
    auto   run     = msg->CanRun();
    delete msg;

    if(!run || status < 0) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    assert(stat && "what ???");

    auto res = _this->setoffset(offset, type, stat->st_size);

    if(res) _cb(0, _data);
    else    _cb(1, _data);
} //}

bool UVFile::truncate(size_t size, TruncateCallback cb, void* data) //{
{
    assert(this->m_fd > 0);
    assert(this->m_error == false);

    uv_fs_t* req = new uv_fs_t();

    if(cb == nullptr) {
        assert(data == nullptr);
        auto rv = uv_fs_ftruncate(this->mp_loop, req, this->m_fd, size, nullptr);
        if(rv < 0) {
            this->m_error = true;
            freereq(req);
            return false;
        }
        this->m_pos = 0;
        return true;
    }

    auto ptr = new uvfile_state(this, reinterpret_cast<void*>(cb), data);
    this->add_callback(ptr);
    uv_req_set_data((uv_req_t*)req, ptr);

    uv_fs_ftruncate(this->mp_loop, req, this->m_fd, size, truncate_callback);
    return true;
} //}
/** [static] */
void UVFile::truncate_callback(uv_fs_t* p_req) //{
{
    CAST_OUT_DATA(TruncateCallback);
    assert(uv_fs_get_type(req.get()) == uv_fs_type::UV_FS_FTRUNCATE);
    
    if(!run) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(req->result < 0) {
        _this->m_error = true;
        _cb(-1, _data);
    } else {
        _cb(0, _data);
        _this->m_pos = 0;
    }
} //}

bool UVFile::reopen(const std::string& filename, int flag, int mode, OpenCallback cb, void* data) //{
{
    if(this->opened() && !this->m_close_error) // FIXME nonblock
        this->close(nullptr, nullptr);
    this->m_filename = filename;
    this->m_fd = -1;
    this->m_pos = 0;
    this->m_error = false;
    this->m_close_error = false;
    this->m_flags = 0;
    this->m_mode = 0;

    if(this->m_watching)
        this->release_file_watcher();
    this->m_watching = true;
    this->register_file_watcher();

    return this->open(flag | O_CREAT, mode, cb, data);
} //}
const std::string& UVFile::filename() {return this->m_filename;}

bool UVFile::opened() {return this->m_fd > 0;}
bool UVFile::error()  {return this->m_error;}
int  UVFile::mode()   {return this->m_mode;}
int  UVFile::flags()  {return this->m_flags;}

static void clean_close_callback(uv_fs_t* req) {freereq(req);}
UVFile::~UVFile() //{
{
    if(this->m_fd > 0 && !this->m_close_error) {
        uv_fs_t* req = new uv_fs_t();
        uv_fs_close(this->mp_loop, req, this->m_fd, clean_close_callback);
    }
    if(this->m_watching) this->release_file_watcher();
} //}

