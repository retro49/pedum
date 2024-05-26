#include <stdio.h>
#include <stdlib.h>

#include "i_types.h"

#define I_STRM_FOPEN_R "r"
#define I_STRM_FOPEN_W "w"
#define I_STRM_FOPEN_A "a"
#define I_STRM_FOPEN_B "b"

typedef FILE* i_fstream;

i_fstream* i_fstream_open(const u8*);

i_result i_fr8(i_fstream*, u8*);
i_result i_fr16(i_fstream*, u16*);
i_result i_fr32(i_fstream*, u32*);
i_result i_fr64(i_fstream*, u64*);
i_result i_fr(i_fstream*, size_t s, void*);

void i_fstream_close(i_fstream*);
