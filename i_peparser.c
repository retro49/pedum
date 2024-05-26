#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "i_peparser.h"
#include "i_types.h"
#include "i_stream.h"


i_pe_ctx*  __attribute__((warn_unused_result)) i_pe_ctx_new(void)
{
    i_pe_ctx* ctx = (i_pe_ctx*)malloc(sizeof(i_pe_ctx));
    if(ctx == NULL)return NULL;

    ctx->is_dos = i_dos_is_dos_hdr;
    ctx->parse_dos_header = i_dos_parser;

    ctx->parse_nt_header = i_pe_parse_nt_hdr;
    ctx->parse_section_table = i_pe_parse_section_table;
    ctx->parse_import_descriptor = i_pe_parse_import_descriptor;
    ctx->parse_import_address_table = i_pe_parse_import_address_table;

    ctx->parse_function_table = i_pe_parse_function_table;
    ctx->parse_functions = i_pe_parse_functions;

    ctx->rva_to_offset = i_pe_rva_to_offset;
    ctx->count_import_descriptor = i_pe_count_import_descriptor;
    ctx->count_import_address_table = i_pe_count_import_address_table;

    ctx->is32bit = i_pe_ctx_is32bit;
    ctx->is64bit = i_pe_ctx_is64bit;

    ctx->ctx_parse = i_ctx_parser;
    ctx->ctx_free = i_pe_ctx_free;

    return ctx;
}

bool i_dos_is_dos_hdr(i_pe_ctx* ctx)
{
    return (ctx->dos_header->i_e_magic== I_DOS_MAGIC) ? true : false;
}

/// parses a dos header
i_result i_dos_parser(i_pe_ctx* ctx, i_fstream* f)
{
    if(ctx == NULL)return I_FAILURE;
    if(f == NULL || *f == NULL)return I_FAILURE;
    if(fseek(*f, 0, 0) != 0)return I_FAILURE;
    fread(ctx->dos_header, sizeof(struct i_dos_header), 1, *f);
    fseek(*f, 0, 0);
    return I_SUCCESS;
}

i_result i_ctx_parser(i_pe_ctx* ctx, i_fstream* f)
{
    if(ctx == NULL || f == NULL || *f == NULL)goto clean_up;
    struct i_dos_header* dos_header = (struct i_dos_header*)
        malloc(sizeof(struct i_dos_header));
    if(dos_header == NULL)goto clean_up;
    ctx->dos_header = dos_header;
    if(ctx->parse_dos_header(ctx, f) == I_FAILURE)goto clean_up;

    struct i_pe_nt_header* nt_header = (struct i_pe_nt_header*)
        malloc(sizeof(struct i_pe_nt_header));
    if(nt_header == NULL)goto clean_up;
    ctx->nt_header = nt_header;
    if(ctx->parse_nt_header(ctx, f) == I_FAILURE)goto clean_up;

    if(ctx->nt_header->i_file_header.i_nsections == 0)goto clean_up;
    struct i_pe_section_table* tbls = (struct i_pe_section_table*)
        malloc(sizeof(struct i_pe_section_table) * ctx->nt_header->i_file_header.i_nsections);
    if(tbls == NULL)goto clean_up;
    ctx->section_tables = tbls;
    if(ctx->parse_section_table(ctx, f) == I_FAILURE)goto clean_up;

    i64 count = ctx->count_import_descriptor(ctx, f);
    if(count == 0)goto clean_up;
    ctx->import_desc_len = count;
    struct i_pe_import_descriptor* import_desc = (struct i_pe_import_descriptor*)
        malloc(sizeof(struct i_pe_import_descriptor) * ctx->import_desc_len);
    if(import_desc == NULL)goto clean_up;
    ctx->import_descriptors = import_desc;
    if(ctx->parse_import_descriptor(ctx, f) == I_FAILURE)goto clean_up;

    struct i_pe_function_table* function_tables = (struct i_pe_function_table*)
        malloc(sizeof(struct i_pe_function_table) * ctx->import_desc_len);
    if(function_tables == NULL)goto clean_up;
    ctx->function_table = function_tables;
    if(ctx->parse_function_table(ctx, f) == I_FAILURE)goto clean_up;

    for(size_t i = 0; i < ctx->import_desc_len; i++){
        struct i_pe_function_table* ftbl = ctx->function_table + i;
        if(ftbl == NULL)
            goto clean_up;
        i64 iat_len = ftbl->i_pe_iat_len;
        if(iat_len == 0)continue;
        if(ctx->is32bit(ctx)){
            struct i_pe_thunk_data32* data32 = (struct i_pe_thunk_data32*)
                malloc(sizeof(struct i_pe_thunk_data32) * iat_len);
            if(data32 == NULL)goto clean_up;
            ftbl->i_data.i_data32 = data32;
        }
        if(ctx->is64bit(ctx)){
            struct i_pe_thunk_data64* data64 = (struct i_pe_thunk_data64*)
                malloc(sizeof(struct i_pe_thunk_data64) * iat_len);
            if(data64== NULL)goto clean_up;
            ftbl->i_data.i_data64 = data64;
        }
    }

    if(ctx->parse_import_address_table(ctx, f) == I_FAILURE)goto clean_up;
    if(ctx->parse_functions(ctx, f) == I_FAILURE)goto clean_up;

    return I_SUCCESS;
    /// clean up is not currently not corrent
    #warning
clean_up:
    if(ctx == NULL)return I_FAILURE;
    bool is32bit = ctx->is32bit(ctx);
    bool is64bit = ctx->is64bit(ctx);

    struct i_dos_header* f_dos_header = ctx->dos_header;
    if(f_dos_header != NULL){
        free(f_dos_header);
        f_dos_header = NULL;
        ctx->dos_header = (struct i_dos_header*)0;
    }

    struct i_pe_nt_header* f_nt_header = ctx->nt_header;
    if(f_nt_header != NULL){
        free(f_nt_header);
        f_nt_header = NULL;
        ctx->nt_header = (struct i_pe_nt_header*)0;
    }

    struct i_pe_section_table* sec = ctx->section_tables;
    if(sec != NULL){
        free(sec);
    }
    struct i_pe_import_descriptor* idesc = ctx->import_descriptors;
    if(idesc != NULL){
        free(idesc);
    }

    struct i_pe_function_table* ftbls;
    for(size_t i = 0; i < ctx->import_desc_len; i++){
        ftbls = ctx->function_table + i;
        if(ftbls == NULL)continue;

        i64 iat_len = ftbls->i_pe_iat_len;
        bool is_ordinal = ftbls->i_is_ordinal;
        if(ftbls != NULL){
            u8* dll_name = ftbls->i_pe_dll_name;
            if(dll_name != NULL)free(dll_name);

            if(is32bit){
                free(ftbls->i_data.i_data32);
            }

            if(is64bit){
                free(ftbls->i_data.i_data64);
            }

            if(is_ordinal){
                void* ptr = ftbls->ord_non_ord;
                if(ptr != NULL)
                    free(ptr);
            } else {
                void** ptr = ftbls->ord_non_ord;
                if(ptr != NULL){
                    for(size_t n = 0; n < ftbls->i_pe_iat_len; n++){
                        void* mem = *(ptr + n);
                        if(mem != NULL)free(mem);
                    }
                }
                free(ptr);
            }
        }
    }

    if(ctx->function_table != NULL)
        free(ctx->function_table);
    if(ctx != NULL)
        free(ctx);
    ctx = NULL;

    return I_FAILURE;
}

void i_pe_ctx_free(i_pe_ctx* ctx)
{
    if(ctx == NULL)return;
    bool is32bit = ctx->is32bit(ctx);
    bool is64bit = ctx->is64bit(ctx);
    struct i_dos_header* dos_header = ctx->dos_header;
    if(dos_header != NULL){
        free(dos_header);
        dos_header = NULL;
        ctx->dos_header = (struct i_dos_header*)0;
    }

    struct i_pe_nt_header* nt_header = ctx->nt_header;
    if(nt_header != NULL){
        free(nt_header);
        nt_header = NULL;
        ctx->nt_header = (struct i_pe_nt_header*)0;
    }

    struct i_pe_section_table* sec = ctx->section_tables;
    if(sec != NULL){
        free(sec);
    }
    struct i_pe_import_descriptor* idesc = ctx->import_descriptors;
    if(idesc != NULL){
        free(idesc);
    }

    struct i_pe_function_table* ftbls;
    for(size_t i = 0; i < ctx->import_desc_len; i++){
        ftbls = ctx->function_table + i;
        i64 iat_len = ftbls->i_pe_iat_len;
        bool is_ordinal = ftbls->i_is_ordinal;
        if(ftbls != NULL){
            u8* dll_name = ftbls->i_pe_dll_name;
            if(dll_name != NULL)free(dll_name);

            if(is32bit){
                free(ftbls->i_data.i_data32);
            }

            if(is64bit){
                free(ftbls->i_data.i_data64);
            }

            if(is_ordinal){
                void* ptr = ftbls->ord_non_ord;
                if(ptr != NULL)
                    free(ptr);
            } else {
                void** ptr = ftbls->ord_non_ord;
                if(ptr != NULL){
                    for(size_t n = 0; n < ftbls->i_pe_iat_len; n++){
                        void* mem = *(ptr + n);
                        if(mem != NULL)free(mem);
                    }
                }
                free(ptr);
            }
        }
    }

    if(ctx->function_table != NULL)
        free(ctx->function_table);
    if(ctx != NULL)
        free(ctx);
    ctx = NULL;
}


i_result i_pe_parse_nt_hdr(i_pe_ctx* ctx, i_fstream* f)
{
#define SEC_READ8(BUFF)\
    if(i_fr8(f, &(BUFF)) == I_FAILURE){goto clean_up;}
#define SEC_READ16(BUFF)\
    if(i_fr16(f, &(BUFF)) == I_FAILURE){goto clean_up;}
#define SEC_READ32(BUFF)\
    if(i_fr32(f, &(BUFF)) == I_FAILURE){goto clean_up;}
#define SEC_READ64(BUFF)\
    if(i_fr64(f, &(BUFF)) == I_FAILURE){goto clean_up;}

    if(ctx == NULL || f == NULL || *f == NULL)goto clean_up;
    if(ctx->nt_header == NULL || ctx->dos_header == NULL)return I_FAILURE;
    u32 lfanew = ctx->dos_header->i_e_lfanew;
    u32 pe_off;

    if(0 != fseek(*f, lfanew, 0))goto clean_up;

    SEC_READ32(ctx->nt_header->i_signature);

    SEC_READ16(ctx->nt_header->i_file_header.i_machine);
    SEC_READ16(ctx->nt_header->i_file_header.i_nsections);
    SEC_READ32(ctx->nt_header->i_file_header.i_time_date_stamp);
    SEC_READ32(ctx->nt_header->i_file_header.i_ptr_to_symbol_tbl);
    SEC_READ32(ctx->nt_header->i_file_header.i_nsymbols);
    SEC_READ16(ctx->nt_header->i_file_header.i_sizeof_optional_hdr);
    SEC_READ16(ctx->nt_header->i_file_header.i_characterstics);

    SEC_READ16(ctx->nt_header->i_opt_hdr.i_magic);
    SEC_READ8(ctx->nt_header->i_opt_hdr.i_major_linker_version);
    SEC_READ8(ctx->nt_header->i_opt_hdr.i_minor_linker_version);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_sizeof_code);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_sizeof_init_data);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_sizeof_uninit_data);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_addr_entry_point);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_base_of_code);
    if(ctx->is32bit(ctx)){
        SEC_READ32(ctx->nt_header->i_opt_hdr.i_base_of_data);
    }

    if(ctx->is32bit(ctx)){
        SEC_READ32(ctx->nt_header->i_opt_hdr.i_image_base.base32);
    } else if(ctx->is64bit(ctx)){
        SEC_READ64(ctx->nt_header->i_opt_hdr.i_image_base.base64);
    } else {
    }

    SEC_READ32(ctx->nt_header->i_opt_hdr.i_section_alignment);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_file_alignment);

    SEC_READ16(ctx->nt_header->i_opt_hdr.i_major_operating_system_version);
    SEC_READ16(ctx->nt_header->i_opt_hdr.i_minor_operating_system_version);
    SEC_READ16(ctx->nt_header->i_opt_hdr.i_major_image_version);
    SEC_READ16(ctx->nt_header->i_opt_hdr.i_minor_image_version);
    SEC_READ16(ctx->nt_header->i_opt_hdr.i_major_subsystem_version);
    SEC_READ16(ctx->nt_header->i_opt_hdr.i_minor_subsystem_version);

    SEC_READ32(ctx->nt_header->i_opt_hdr.i_win32_version_value);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_sizeof_image);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_sizeof_headers);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_checksum);

    SEC_READ16(ctx->nt_header->i_opt_hdr.i_subsystem);
    SEC_READ16(ctx->nt_header->i_opt_hdr.i_dll_characteristics);

    if(ctx->is32bit(ctx)){
        SEC_READ32(ctx->nt_header->i_opt_hdr.i_stack_reserve.reserve32);
        SEC_READ32(ctx->nt_header->i_opt_hdr.i_stack_commit.commit32);
        SEC_READ32(ctx->nt_header->i_opt_hdr.i_heap_reserve.reserve32);
        SEC_READ32(ctx->nt_header->i_opt_hdr.i_heap_commit.commit32);
    } 
    if(ctx->is64bit(ctx)){
        SEC_READ64(ctx->nt_header->i_opt_hdr.i_stack_reserve.reserve64);
        SEC_READ64(ctx->nt_header->i_opt_hdr.i_stack_commit.commit64);
        SEC_READ64(ctx->nt_header->i_opt_hdr.i_heap_reserve.reserve64);
        SEC_READ64(ctx->nt_header->i_opt_hdr.i_heap_commit.commit64);
    } 

    SEC_READ32(ctx->nt_header->i_opt_hdr.i_loader_flags);
    SEC_READ32(ctx->nt_header->i_opt_hdr.i_num_of_rva_and_sizes);
    for(size_t i = 0; i < ctx->nt_header->i_opt_hdr.i_num_of_rva_and_sizes; i++){
        if(fread(&(ctx->nt_header->i_opt_hdr.i_data_dir[i]),
                 sizeof(struct i_pe_data_dir), 1, *f) == 0)goto clean_up;
    }

    ctx->section_table_offset = 
        ctx->dos_header->i_e_lfanew 
        + sizeof(ctx->nt_header->i_signature)
        + ctx->nt_header->i_file_header.i_sizeof_optional_hdr
        + sizeof(struct i_pe_file_header);

    fseek(*f, 0, 0);
    return I_SUCCESS;
clean_up:
    fseek(*f, 0, 0);
    return I_FAILURE;
}


bool i_pe_ctx_is32bit(i_pe_ctx* ctx)
{
    if(ctx == NULL)return false;
    if(ctx->nt_header == NULL)return false;
    return ctx->nt_header->i_opt_hdr.i_magic == I_PE_IMG_OPT_MAGIC_HDR32;
}

bool i_pe_ctx_is64bit(i_pe_ctx* ctx)
{
    if(ctx == NULL)return false;
    if(ctx->nt_header == NULL)return false;
    return ctx->nt_header->i_opt_hdr.i_magic == I_PE_IMG_OPT_MAGIC_HDR64;
}

i_result i_pe_parse_section_table(i_pe_ctx* ctx, i_fstream* f)
{
    if(ctx == NULL || f == NULL || *f == NULL)goto clean_up;
    if(0 != fseek(*f, ctx->section_table_offset, 0))goto clean_up;
    for(size_t i = 0; i < ctx->nt_header->i_file_header.i_nsections; i++){
        if(fread((ctx->section_tables + i), 
                 sizeof(struct i_pe_section_table), 1, *f) == 0)goto clean_up;
    }
    return I_SUCCESS;

clean_up:
    fseek(*f, 0, 0);
    return I_FAILURE;
}


i_result i_pe_parse_import_descriptor(i_pe_ctx* ctx, i_fstream* f)
{
    if(ctx == NULL || f == NULL || *f == NULL)goto clean_up;
    if(ctx->import_descriptors == NULL)goto clean_up;
    i64 offset = ctx->rva_to_offset(ctx, ctx->nt_header->i_opt_hdr.i_data_dir[1].i_virtual_address);
    if(0 != fseek(*f, offset, 0))goto clean_up;
    for(int i = 0; i < ctx->import_desc_len; i++){
        if(fread((ctx->import_descriptors + i), sizeof(struct i_pe_import_descriptor), 1, *f) == 0)
            goto clean_up;
    }
    return I_SUCCESS;
clean_up:
    return I_FAILURE;
}

i_result i_pe_parse_function_table(i_pe_ctx* ctx, i_fstream* f)
{
    if(ctx == NULL || f == NULL || *f == NULL)return I_FAILURE;
    struct i_pe_import_descriptor* desc;
    struct i_pe_function_table* ftbl;
    for(size_t i = 0; i < ctx->import_desc_len; i++){
        desc = (ctx->import_descriptors + i);
        ftbl = (ctx->function_table + i);

        ftbl->i_pe_dll_name_rva = desc->i_name;
        ftbl->i_pe_iat_rva = desc->DUMMYUNINAME.i_original_first_thunk;
        ftbl->i_pe_iat_len = i_pe_count_import_address_table(ctx, f, ftbl->i_pe_iat_rva);
        ftbl->i_pe_dll_name = i_util_readstr(f, ctx->rva_to_offset(ctx, ftbl->i_pe_dll_name_rva));
        ftbl->i_import_desc = desc;
    }
    return I_SUCCESS;
clean_up:
    return I_FAILURE;
}

i_result i_pe_parse_import_address_table(i_pe_ctx* ctx, i_fstream* f)
{
    if(ctx == NULL || f == NULL || *f == NULL)return I_FAILURE;
    for(size_t i = 0; i < ctx->import_desc_len; i++){
        struct i_pe_function_table* ftbl = ctx->function_table + i;
        if(ftbl == NULL)return I_FAILURE;

        i64 iat_rva = ftbl->i_pe_iat_rva;
        i64 off = ctx->rva_to_offset(ctx, iat_rva);
        if(off == 0)goto clean_up;
        if(0 != fseek(*f, off, 0))goto clean_up;

        for(size_t j = 0; j < ftbl->i_pe_iat_len; j++){
            if(ctx->is32bit(ctx)){
                fread((ftbl->i_data.i_data32 + j),
                      sizeof(struct i_pe_thunk_data32),
                      1, *f);
            } else if(ctx->is64bit(ctx)){
                fread((ftbl->i_data.i_data64 + j),
                      sizeof(struct i_pe_thunk_data64),
                      1, *f);
            }
        }
    }
    return I_SUCCESS;
clean_up:
    return I_FAILURE;
}

i_result _i_pe_parse_ordinals(struct i_pe_function_table* tbl, i_fstream* f, bool bit32)
{
    if(tbl == NULL || f == NULL)return I_FAILURE;
    u16* ordinals = (u16*)malloc(sizeof(u16) * tbl->i_pe_iat_len);
    if(ordinals == NULL)return I_FAILURE;
    for(size_t i = 0; i < tbl->i_pe_iat_len; i++){
        if(bit32){
            u32 ord = (tbl->i_data.i_data32 +i)->i_thunk_data32.i_address_of_data;
            *(ordinals + i) = ord; // & 0xffff;
        } else {
            u64 ord = (tbl->i_data.i_data64 +i)->i_thunk_data64.i_address_of_data;
            *(ordinals + i) = ord; // & 0xffff;
        }
    } 
    tbl->i_rep.i_ordinal = ordinals;
    tbl->ord_non_ord = ordinals;
    return I_SUCCESS;
}

i_result _i_pe_parse_nonordinals(struct i_pe_ctx* ctx, struct i_pe_function_table* tbl, i_fstream* f, bool bit32)
{
    if(ctx == NULL || tbl == NULL || f == NULL)return I_FAILURE;
    u8** fptr = (u8**)malloc(sizeof(u8*) * tbl->i_pe_iat_len);
    if(fptr == NULL)return I_FAILURE;
    tbl->i_rep.i_function = fptr;
    for(size_t i = 0; i < tbl->i_pe_iat_len; i++){
        if(bit32){
            i32 rva = (tbl->i_data.i_data32 + i)->i_thunk_data32.i_address_of_data;
            i64 off = ctx->rva_to_offset(ctx, rva) + 0x02;
            u8* fname = i_util_readstr(f, off);
            if(fname == NULL)goto clean_up;
            *(tbl->i_rep.i_function + i) = fname;
        } else {
            i64 rva = (tbl->i_data.i_data64 + i)->i_thunk_data64.i_address_of_data;
            i64 off = ctx->rva_to_offset(ctx, rva) + 0x02;
            u8* fname = i_util_readstr(f, off);
            if(fname == NULL)goto clean_up;
            *(tbl->i_rep.i_function + i) = fname;
        }
    }
    tbl->ord_non_ord= fptr;
    return I_SUCCESS;
clean_up:
    return I_FAILURE;
}

i_result i_pe_parse_functions(i_pe_ctx* ctx, i_fstream* f)
{
    if(f == NULL || *f == NULL || ctx == NULL)return I_FAILURE;
    if(ctx->function_table == NULL)return I_FAILURE;
    bool is32bit = ctx->is32bit(ctx);
    bool is64bit = ctx->is64bit(ctx);
    for(size_t i = 0; i < ctx->import_desc_len; i++){
        struct i_pe_function_table* tbl = ctx->function_table + i;
        if(tbl == NULL)continue;
        if(is32bit){
            //u32 oft = tbl->i_data32->i_address_of_data;
            u32 oft = tbl->i_data.i_data32->i_thunk_data32.i_address_of_data;
            if(oft & 0x80000000){
                tbl->i_is_ordinal = true;
            } else {
                tbl->i_is_ordinal = false;
            }
        } 

        // okay right here...
        // TODO: must be watched
        if(is64bit){
            // u32 oft = tbl->i_data32->i_address_of_data;
            u32 oft = tbl->i_data.i_data32->i_thunk_data32.i_address_of_data;
            if(oft & 0x80000000){
                tbl->i_is_ordinal = true;
            } else {
                tbl->i_is_ordinal = false;
            }
        }

        if(tbl->i_is_ordinal){
            _i_pe_parse_ordinals(tbl, f, is32bit);
        } else{
            _i_pe_parse_nonordinals(ctx, tbl, f, ctx->is32bit(ctx));
        }
    }
    return I_SUCCESS;
    // here we go
clean_up:
    return I_FAILURE;
}


i64 i_pe_rva_to_offset(i_pe_ctx* ctx, i64 rva)
{
    if(ctx == NULL)return 0;
    if(ctx->section_tables == NULL)return 0;
    for(size_t i = 0; i < ctx->nt_header->i_file_header.i_nsections; i++){
        i32 section_start = (ctx->section_tables + i)->i_virtual_address;
        i32 section_end = section_start + (ctx->section_tables + i)->phvi.i_virtual_size;
        if(rva >= section_start && rva < section_end){
            return (ctx->section_tables + i)->i_pointer_to_raw_data +
            (rva - (ctx->section_tables + i)->i_virtual_address);
        }
    }
    return 0;
}

i64 i_pe_count_import_descriptor(i_pe_ctx* ctx, i_fstream* f)
{
    i64 count = 0;
    i64 offset = ctx->rva_to_offset(ctx, ctx->nt_header->i_opt_hdr.i_data_dir[1].i_virtual_address);
    if(0 != fseek(*f, offset, 0))goto clean_up;
    struct i_pe_import_descriptor descriptor;
loop:
    if(fread(&descriptor, sizeof(descriptor), 1, *f) == 0)goto clean_up;
    if(descriptor.DUMMYUNINAME.i_characteristics == 0 &&
        descriptor.i_first_thunk == 0 &&
        descriptor.i_forwarder_chain == 0 &&
        descriptor.i_name == 0 &&
        descriptor.i_time_date_stamp == 0)goto breaker;
    count += 1;
    goto loop;
breaker:
    return count;

clean_up:
    return 0;
}


bool i_pe_validate_pe_hdr(i_pe_ctx* ctx)
{
    if(ctx == NULL || ctx->nt_header == NULL)return false;
    return (ctx->nt_header->i_signature == I_PE_SIGNATURE) ? true : false;
}

i64 i_pe_count_import_address_table(i_pe_ctx* ctx, i_fstream* f, i64 rva)
{
    if(ctx == NULL || f == NULL || *f == NULL)return 0;
    if(rva == 0)return 0;
    struct i_pe_thunk_data32 bit32;
    struct i_pe_thunk_data64 bit64;
    i64 off = ctx->rva_to_offset(ctx, rva);
    if(off == 0)return 0;
    if(0 != fseek(*f, off, 0))return 0;
    i64 count = 0;
    if(ctx->is32bit(ctx))goto loop32;
    if(ctx->is64bit(ctx))goto loop64;
loop32:
    if(0 == fread(&bit32,sizeof(struct i_pe_thunk_data32), 1, *f)){
        count = 0;
        goto end;
    }
    if(bit32.i_thunk_data32.i_address_of_data == 0)goto end;
    count += 1;
    goto  loop32;

loop64:
    if(0 ==  fread(&bit64,sizeof(struct i_pe_thunk_data64), 1, *f)){
        count = 0;
        goto end;
    }

    if(bit64.i_thunk_data64.i_address_of_data == 0)goto end;
    count += 1;
    goto loop64;
end:
    fseek(*f, 0, 0);
    return count;
}

/// varify a dos header from a stream.
bool i_dos_validate_dos_stream(i_fstream* strm)
{
    u8 mag[2];
    memset(mag, 0, sizeof(u8)*2);
    fread(mag, sizeof(u8), 2, *strm);
    fseek(*strm, 0, 0);
    return memcmp(mag, I_DOS_MAGIC_MZ, sizeof(char)*2) == 0 
    ? true : false;
}

/// Validates if a given stream is a pe file or not.
/// if a stream is closed the returned value is false.
bool i_pe_validate_pe_strm(i_fstream* strm)
{
    if(strm == NULL || *strm == NULL)return false;
    u32 e_lfanew = 0, ipe_sig  = 0;
    bool res;
    if(fseek(*strm, (1<<6) - 4, 0) != 0){
        res = false;
        goto i_clean;
    }
    fread(&e_lfanew, sizeof(i32), 1, *strm);
    if(fseek(*strm, e_lfanew, 0) != 0){
        res = false;
        goto i_clean;
    }
    fread(&ipe_sig, sizeof(u32), 1, *strm);
    if(ipe_sig != I_PE_SIGNATURE){
        res = false;
    } else {
        res = true;
    }
i_clean:
    fseek(*strm, 0, 0);  // man this must not fail
    return res;
}

i64 i_util_readstr_len(i_fstream* f, i64 off)
{
    if(0 != fseek(*f, off, 0))return 0;
    i64 len = 0;
    i32 chr;
    while((chr = fgetc(*f) != 0))len++;
    return len;
}

u8* i_util_readstr(i_fstream* f, i64 off)
{
    if(f == NULL || *f == NULL)return NULL;
    i64 len = i_util_readstr_len(f, off);
    if(0 != fseek(*f, off, 0))return NULL;
    u8* buff = (u8*)malloc(sizeof(u8) * (len + 1));
    if(buff == NULL)return NULL;
    i64 c = 0;
    while((*(buff + c) = fgetc(*f)) != 0)c++;
    *(buff + len) = 0;
    return buff;;
}
