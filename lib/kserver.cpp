#include "../include/kserver.h"

#include <uv.h>

#include <stdlib.h>

#include <tuple>


namespace KProxyServer {

ServerToNetConnection::ServerToNetConnection(const sockaddr* addr, ConnectionId id, ClientConnectionProxy* p, uv_read_cb rcb) //{
{
    this->m_connectionWrapper = p;
    this->m_read_callback = rcb;
    this->id = id;
    this->used_buffer_size = 0;
    this->mp_tcp = new uv_tcp_t();

    uv_handle_set_data((uv_handle_t*)this->mp_tcp, this);

    uv_connect_t* p_req = new uv_connect_t();
    uv_req_set_data((uv_req_t*)p_req, this);

    uv_tcp_connect(p_req, this->mp_tcp, addr, 
            [](uv_connect_t* req, int status) {
                ServerToNetConnection* _this = (ServerToNetConnection*)uv_req_get_data((uv_req_t*)req);

                delete req;

                if(status < 0) {
                    // TODO
                }

                uv_read_start((uv_stream_t*)_this->mp_tcp, 
                        [](uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
                            buf->base = (char*)malloc(suggested_size);
                            buf->len  = suggested_size;
                            return;
                        }, 
                        [](uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
                            if(nread < 0) {
                                // TODO
                            } else if (nread == 0) { // EOF
                                // TODO
                            }
                            ServerToNetConnection* _this = (ServerToNetConnection*)uv_handle_get_data((uv_handle_t*)handle);
                            _this->realy_back(*buf);
                            return;
                        });
            });
} //}

ServerToNetConnection::~ServerToNetConnection() //{
{
    delete this->mp_tcp;
    this->mp_tcp = nullptr;
} //}

int ServerToNetConnection::write(uv_buf_t bufs[], unsigned int nbufs, uv_write_cb cb) //{
{
    using data_type = std::tuple<typeof(this), typeof(cb)>;

    uv_write_t* p_req = new uv_write_t();
    uv_req_set_data((uv_req_t*)p_req, new data_type(this, cb));

    for(int i=0;i<nbufs;i++)
        this->used_buffer_size += bufs[i].len;

    return uv_write(p_req, (uv_stream_t*)this->mp_tcp, bufs, nbufs, 
            [](uv_write_t* req, int status) -> void {
                data_type* x = static_cast<data_type*>(uv_req_get_data((uv_req_t*)req));
                ServerToNetConnection* _this = std::get<0>(*x);
                uv_write_cb cb = std::get<1>(*x);
                delete x;
                
                for(int i=0;i<req->nbufs;i++)
                    _this->used_buffer_size -= req->bufs[i].len;

                cb(req, status);
            });
} //}

}
