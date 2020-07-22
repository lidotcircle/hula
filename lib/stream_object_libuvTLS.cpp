#include "../include/stream_object_libuvTLS.h"
#include "../include/config.h"
#include <assert.h>


StreamObjectUVTLS::StreamObjectUVTLS(size_t max_buffer_size, UNST stream): //{
   EBStreamObject(max_buffer_size), EBStreamUVTLS(stream)
{
} //}

StreamObjectUVTLS::StreamObjectUVTLS(size_t max_buffer_size, TLSMode mode, UNST stream, 
                                     const std::string& cert, const std::string& privateKey): //{
   EBStreamObject(max_buffer_size), EBStreamUVTLS(stream, mode, cert, privateKey)
{
} //}

StreamObjectUVTLS::StreamObjectUVTLS(size_t max_buffer_size, TLSMode mode, uv_tcp_t* stream, 
                                     const std::string& cert, const std::string& privateKey): //{
   EBStreamObject(max_buffer_size), EBStreamUVTLS(stream, mode, cert, privateKey)
{
} //}


bool StreamObjectUVTLS::accept(EBStreamObject*) {return false;}

EBStreamObject* StreamObjectUVTLS::NewStreamObject(UNST stream) //{
{
    assert(stream->getType() == this->getType());
    return new StreamObjectUVTLS(NEW_STREAM_OBJECT_BUFFER_SIZE, stream);
} //}

