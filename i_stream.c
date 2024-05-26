#include <stdio.h>
#include <stdlib.h>
#include "i_types.h"
#include "i_stream.h"

/// opens a stream from a file path
i_fstream* i_fstream_open(const u8* path)
{
    if(path == NULL)return NULL;
    i_fstream* stream;
    stream = (i_fstream*)malloc(sizeof(i_fstream));
    if(stream == NULL)return NULL;
    *stream = (i_fstream)
        fopen((const char*)path, I_STRM_FOPEN_R""I_STRM_FOPEN_B);
    if(*stream == NULL)return NULL;
    return stream;
}

inline i_result i_fr8(i_fstream* f, u8* buff)
{
    return fread(buff, sizeof(u8), 1, *f) == 0 ? 
        I_FAILURE : I_SUCCESS;
}

inline i_result i_fr16(i_fstream* f, u16* buff)
{
    return fread(buff, sizeof(u16), 1, *f) == 0 ?
        I_FAILURE : I_SUCCESS;
}

inline i_result i_fr32(i_fstream* f, u32* buff)
{
    return fread(buff, sizeof(u32), 1, *f) == 0 ?
        I_FAILURE : I_SUCCESS;
}

inline i_result i_fr64(i_fstream* f, u64* buff)
{
    return fread(buff, sizeof(u64), 1, *f) == 0 ?
        I_FAILURE : I_SUCCESS;
}

inline i_result i_fr(i_fstream* f, size_t size, void* buffer)
{
    return fread(buffer, size, 1, *f) == 0 ?
        I_FAILURE : I_SUCCESS;
}
/// closes a file stream. Must be closed if
/// only opened by i_fstream_open
void i_fstream_close(i_fstream* stream)
{
    if(stream == NULL)return;
    if(*stream == NULL){
        free(stream);
        return;
    }
    fclose((FILE*)*stream);
    *stream = NULL; // take care here
    if(stream != NULL){
        free(stream);
    }
}
