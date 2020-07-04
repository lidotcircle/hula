#include "../include/config_file.h"
#include "../include/config.h"

#include <assert.h>
#include <stdio.h>
#include <uv.h>


struct load_state: public CallbackPointer {
    ConfigFile* _this;
    ConfigFile::LoadCallback _cb;
    void* _data;
    load_state(decltype(_this) _this, decltype(_cb) cb, void* data): _this(_this), _cb(cb), _data(data) {}
};
bool ConfigFile::loadFromFile(LoadCallback cb, void* data) //{
{
    this->clearError();

    load_state* ptr = nullptr;
    if(cb != nullptr) {
        ptr = new load_state(this, cb, data);
        this->add_callback(ptr);
    } else assert(data == nullptr);

    bool seek = true;
    if(!this->opened()) {
        if(cb == nullptr) {
            auto rv = this->open(O_RDWR, 0644, nullptr, nullptr);
            if(!rv) {
                this->setError("open() fail");
                return false;
            }
            seek = false;
        } else {
            this->open(O_RDWR, 0644, open_callback, ptr);
            return true;
        }
    }

    assert(this->opened());
    if(seek) {
        if(cb == nullptr) {
            auto rv = this->seek(0, SeekType::START, nullptr, nullptr);
            if(!rv) {
                this->setError("seek() fail");
                return false;
            }
        } else {
            this->seek(0, SeekType::START, seek_callback, ptr);
            return true;
        }
    }

    ROBuf buf;
    if(cb == nullptr) {
        buf = this->readremain(nullptr, nullptr);
        if(buf.size() == 0) {
            this->setError("readremain() fail");
            return false;
        }
    } else {
        this->readremain(read_callback, ptr);
        return true;
    }

    if(this->fromROBuf(buf)) {
        return true;
    } else {
        return false;
    }
} //}

#define CASTOUT()  \
    load_state* msg = \
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data)); \
    assert(msg); \
    auto _this = msg->_this; \
    auto _cb = msg->_cb; \
    auto _data = msg->_data; \
    auto run = msg->CanRun();
/** [static] */
void ConfigFile::open_callback(int status, void* data) //{
{
    CASTOUT();

    if(!run) {
        delete msg;
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(status < 0) {
        _this->setError("open() fail");
        delete msg;
        _cb(-1, _data);
        return;
    }

    _this->add_callback(msg);
    _this->readremain(read_callback, msg);
} //}
/** [static] */
void ConfigFile::seek_callback(int status, void* data) //{
{
    CASTOUT();

    if(!run) {
        delete msg;
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(status < 0) {
        _this->setError("seek() fail");
        delete msg;
        _cb(-1, _data);
        return;
    }

    _this->add_callback(msg);
    _this->readremain(read_callback, msg);
} //}
/** [static] */
void ConfigFile::read_callback(ROBuf buf, int status, void* data) //{
{
    CASTOUT();
    delete msg;

    if(!run) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(status < 0) {
        _this->setError("readremain() fail");
        _cb(-1, _data);
        return;
    }

    if(_this->fromROBuf(buf))
        _cb(0, _data);
    else
        _cb(-1, _data);
} //}

/** [static] */
void ConfigFile::close_callback(int status, void* data) {}


using write_state = load_state;
bool ConfigFile::writeToFile(WriteCallback cb, void* data) //{
{
    this->clearError();

    write_state* ptr = nullptr;
    if(cb != nullptr) {
        ptr = new write_state(this, cb, data);
        this->add_callback(ptr);
    } else assert(data == nullptr);

    if(!this->opened()) {
        if(cb == nullptr) {
            auto rv = this->open(O_RDWR | O_CREAT, 0644, nullptr, nullptr);
            if(!rv) {
                this->setError("open fail");
                return false;
            }
        } else {
            this->open(O_RDWR | O_CREAT, 0644, open_callback_for_write, ptr);
            return true;
        }
    }

    assert(this->opened());

    if(cb == nullptr) {
        bool rv = this->truncate(0, nullptr, nullptr);
        if(rv == false) {
            this->setError("truncate() fail");
            return false;
        }
    } else {
        this->truncate(0, truncate_callback_for_write, ptr);
        return true;
    }

    ROBuf buf = this->toROBuf();
    bool rv = this->write(buf, nullptr, nullptr);
    if(rv == false) this->setError("write() fail");
    return rv;
} //}
#define CASTOUT_WRITE()  \
    write_state* msg = \
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data)); \
    assert(msg); \
    auto _this = msg->_this; \
    auto _cb = msg->_cb; \
    auto _data = msg->_data; \
    auto run = msg->CanRun();

/** [static] */
void ConfigFile::open_callback_for_write(int status, void* data) //{
{
    CASTOUT_WRITE();

    if(!run) {
        delete msg;
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(status < 0) {
        _this->setError("open() fail");
        delete msg;
        _cb(-1, _data);
        return;
    }

    _this->add_callback(msg);
    _this->truncate(0, truncate_callback_for_write, msg);
} //}
/** [static] */
void ConfigFile::truncate_callback_for_write(int status, void* data) //{
{
    CASTOUT_WRITE();

    if(!run) {
        delete msg;
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(status < 0) {
        _this->setError("truncate() fail");
        delete msg;
        _cb(-1, _data);
        return;
    }

    ROBuf buf = _this->toROBuf();
    _this->add_callback(msg);
    _this->write(buf, write_callback, msg);
} //}
/** [static] */
void ConfigFile::write_callback(ROBuf buf, int status, void* data) //{
{
    CASTOUT_WRITE();

    delete msg;
    if(!run) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(status < 0) {
        _this->setError("write() error");
        _cb(-1, _data);
    } else {
        _cb(0,  _data);
    }
} //}

bool ConfigFile::setNewFile(const std::string& filename) //{
{
    this->clearError();
    return this->reopen(filename, this->flags(), this->mode(), nullptr, nullptr);
} //}

void ConfigFile::setError(const std::string& error) {this->m_error.push(error);}
void ConfigFile::clearError() {this->m_error = std::stack<std::string>();}

