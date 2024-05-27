#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "i_peparser.h"
#include "i_stream.h"
#include "i_types.h"

void parse_pe(const char*);
void print_dos_header(i_pe_ctx* );
void print_nt_header(i_pe_ctx* );
void print_section_tables(i_pe_ctx* );
void print_import_descriptor(i_pe_ctx* ); 
void print_import_function_iat(i_pe_ctx*);
i_fstream* strm;
int main(int argc, char** argv)
{ 
    if(argc < 2){ fprintf(stdout, "usage: ./dumpit <file>\n");
        return 1;
    } parse_pe(argv[1]);
    return 0;
} 

void parse_pe(const char* path) 
{ 
    strm = i_fstream_open((const u8*)path);
    if(strm == NULL || *strm == NULL){ 
        fprintf(stderr, "file not found: %s\n", path);
        exit(1);
    }

    i_pe_ctx* ctx = i_pe_ctx_new();
    if(ctx == NULL){
        fprintf(stderr, "unable to parse pe file");
        exit(0b10);
    }

    if(ctx->ctx_parse(ctx, strm) == I_FAILURE){
        printf("error parsing file: %s\n", path);
        return;
    }

    print_dos_header(ctx);
    print_nt_header(ctx);
    print_section_tables(ctx);
    print_import_descriptor(ctx);
    print_import_function_iat(ctx);
    printf("TOTAL IMPORTS: %ld\n", ctx->import_desc_len);
    ctx->ctx_free(ctx);
    i_fstream_close(strm);
}

void print_dos_header(i_pe_ctx* ctx)
{
    if(ctx == NULL)exit(1);
    if(ctx->dos_header == NULL)exit(2);
    printf("DOS HEADER: \n");
    printf("%-12s %x\n", "E_MAGIC", ctx->dos_header->i_e_magic);
    printf("%-12s %x\n", "E_CBLP", ctx->dos_header->i_e_cblp);
    printf("%12s %x\n", "E_CP", ctx->dos_header->i_e_cp);
    printf("%-12s %x\n", "E_CRLC", ctx->dos_header->i_e_crlc);
    printf("%-12s %x\n", "E_CPARHDR", ctx->dos_header->i_e_cparhdr);
    printf("%-12s %x\n", "E_MINALLOC", ctx->dos_header->i_e_minalloc);
    printf("%-12s %x\n", "E_MAXALLOC", ctx->dos_header->i_e_maxalloc);
    printf("%-12s %x\n", "E_SS", ctx->dos_header->i_e_ss);
    printf("%-12s %x\n", "E_SP", ctx->dos_header->i_e_sp);
    printf("%-12s %x\n", "E_CSUM", ctx->dos_header->i_e_csum);
    printf("%-12s %x\n", "E_IP", ctx->dos_header->i_e_ip);
    printf("%-12s %x\n", "E_CS", ctx->dos_header->i_e_cs);
    printf("%-12s %x\n", "E_LFARLC", ctx->dos_header->i_e_lfarlc);
    printf("%-12s %x\n", "E_OVNO", ctx->dos_header->i_e_ovno);
    printf("%-12s %x\n", "E_RES", ctx->dos_header->i_e_res);
    printf("%-12s %x\n", "E_OEMID", ctx->dos_header->i_e_oemid);
    printf("%-12s %x\n", "E_OEMINFO", ctx->dos_header->i_e_oeminfo);
    printf("%-12s %x\n", "E_RES2", ctx->dos_header->i_e_res2);
    printf("%-12s %x\n", "E_LFANEW", ctx->dos_header->i_e_lfanew);
}

void print_nt_header(i_pe_ctx* ctx)
{
    if(ctx == NULL)exit(1);
    bool is32bit = ctx->is32bit(ctx);
    bool is64bit = ctx->is64bit(ctx);

    if(ctx->nt_header == NULL)exit(2);
    struct i_pe_file_header fhdr = ctx->nt_header->i_file_header;
    printf("\nNT FILE HEADER:\n");
    printf("%-30s %08x\n", "MACHINE", fhdr.i_machine);
    printf("%-30s %08x\n", "NUMBER OF SECTIONS", fhdr.i_nsections);
    printf("%-30s %08x\n", "TIME DATE STAMP", fhdr.i_time_date_stamp);
    printf("%-30s %08x\n", "POINTER TO SYMBOL TABLE", fhdr.i_ptr_to_symbol_tbl);
    printf("%-30s %08x\n", "NUMBER OF SYMBOLS", fhdr.i_nsymbols);
    printf("%-30s %08x\n", "SIZE OF OPTIONAL HEADER", fhdr.i_sizeof_optional_hdr);
    printf("%-30s %08x\n", "CHARACTERISTICS", fhdr.i_characterstics);

    struct i_pe_optional_header opt = ctx->nt_header->i_opt_hdr;
    printf("\nNT OPOTIONAL HEADER:\n");
    printf("%-30s %08x\n", "MAGIC", opt.i_magic);
    printf("%-30s %d\n", "MAJOR LINKER VERSION", opt.i_major_linker_version);
    printf("%-30s %d\n", "MINOR LINKER VERSION", opt.i_minor_linker_version);
    printf("%-30s %08x\n", "SIZE OF CODE", opt.i_sizeof_code);
    printf("%-30s %08x\n", "SIZE OF INITIALIZED DATA", opt.i_sizeof_init_data);
    printf("%-30s %08x\n", "SIZE OF UNINITIALIZED DATA", opt.i_sizeof_uninit_data);
    printf("%-30s %08x\n", "ADDRESS OF ENTRY POINT", opt.i_addr_entry_point);
    printf("%-30s %08x\n", "BASE OF CODE", opt.i_base_of_code);
    if(is32bit){
        printf("%-30s %08x\n", "BASE OF DATA", opt.i_base_of_data);
    }

    if(is32bit){
        printf("%-30s %08x\n", "IMAGE BASE", opt.i_image_base.base32);
    } else if(is64bit){
        printf("%-30s %08lx\n", "IMAGE BASE", opt.i_image_base.base64);
    }

    printf("%-30s %08x\n", "SECTION ALIGNMENT", opt.i_section_alignment);
    printf("%-30s %08x\n", "FILE ALIGNMENT", opt.i_file_alignment);
    printf("%-30s %d\n", "MAJOR OS VERSION", opt.i_major_operating_system_version);
    printf("%-30s %d\n", "MINOR OS VERSION", opt.i_minor_operating_system_version);
    printf("%-30s %d\n", "MAJOR IMAGE VERSION", opt.i_major_image_version);
    printf("%-30s %d\n", "MINOR IMAGE VERSION", opt.i_minor_image_version);
    printf("%-30s %d\n", "MAJOR SUBSYSTEM VERSION", opt.i_major_subsystem_version);
    printf("%-30s %d\n", "MINOR SUBSYSTEM VERSION", opt.i_minor_subsystem_version);

    printf("%-30s %08x\n", "WINDOWS32 VERSION VALUE", opt.i_win32_version_value);
    printf("%-30s %08x\n", "SIZE OF IMAGE", opt.i_sizeof_image);
    printf("%-30s %08x\n", "SIZE OF HEADERS", opt.i_sizeof_headers);
    printf("%-30s %08x\n", "CHECKSUM", opt.i_checksum);

    printf("%-30s %08x\n", "SUBSYSTEM", opt.i_subsystem);
    printf("%-30s %08x\n", "DLL CHARACTERISTICS", opt.i_dll_characteristics);

    if(is32bit){
        printf("%-30s %08x\n", "SIZE OF STACK RESERVE", opt.i_stack_reserve.reserve32);
        printf("%-30s %08x\n", "SIZE OF STACK COMMIT", opt.i_stack_commit.commit32);
        printf("%-30s %08x\n", "SIZE OF HEAP RESERVE", opt.i_heap_reserve.reserve32);
        printf("%-30s %08x\n", "SIZE OF HEAP COMMIT", opt.i_heap_commit.commit32);
    } else if(is64bit){
        printf("%-30s %08lx\n", "SIZE OF STACK RESERVE", opt.i_stack_reserve.reserve64);
        printf("%-30s %08lx\n", "SIZE OF STACK COMMIT", opt.i_stack_commit.commit64);
        printf("%-30s %08lx\n", "SIZE OF HEAP RESERVE", opt.i_heap_reserve.reserve64);
        printf("%-30s %08lx\n", "SIZE OF HEAP COMMIT", opt.i_heap_commit.commit64);
    } else {
        // YEP NOT HANDLED FOR ROM 
    }

    printf("%-30s %08x\n", "LOADER FLAGS", opt.i_loader_flags);
    printf("%-30s %08x\n", "NUMBER OF RVA AND SIZES", opt.i_num_of_rva_and_sizes);

    printf("\nDATA DIRECTORY\n");
    printf("%-6s %-16s %-8s %s\n","ENTRY", "VIRTUAL_ADDRESS", "SIZE", "NAME");
    for(size_t i = 0; i < opt.i_num_of_rva_and_sizes; i++){
        printf("%-6lx %-16x %-8x %s\n", i, 
                opt.i_data_dir[i].i_virtual_address,
                opt.i_data_dir[i].i_size,
                I_PE_DATA_DIRECTORY_STRING[i]);
    }

}

void print_section_tables(i_pe_ctx* ctx)
{
    if(ctx == NULL)exit(1);
    if(ctx->nt_header == NULL)exit(3);
    printf("\nSECTIONS: \n");
    for(size_t i = 0; i < ctx->nt_header->i_file_header.i_nsections; i++){
        struct i_pe_section_table* sec = ctx->section_tables + i;
        printf("%ld NAME: %s\n", i, sec->i_name);
        printf("\tVIRTUAL SIZE: %x\n", sec->phvi.i_virtual_size);
        printf("\tVIRTUAL ADDRESS: %x\n", sec->i_virtual_address);
        printf("\tSIZE OF RAW DATA: %x\n", sec->i_size_of_raw_data);
        printf("\tPOINTER TO RAW DATA: %x\n", sec->i_pointer_to_raw_data);
        printf("\tPOINTER TO RELOCATIONS: %x\n", sec->i_pointer_to_relocations);
        printf("\tPOINTER TO LINE NUMBERS: %x\n", sec->i_pointer_to_line_numbers);
        printf("\tNUMBER OF RELOCATIONS: %x\n", sec->i_number_of_relocations);
        printf("\tNUMBER OF LINE NUMBERS: %x\n", sec->i_number_of_line_numbers);
        printf("\tCHARACTERISTICS: %x\n", sec->i_characterstics);
    }
}

void print_import_descriptor(i_pe_ctx* ctx)
{
    printf("\nIMPORT DESCRIPTION\n");
    for(size_t i = 0; i < ctx->import_desc_len; i++){
        printf("ORIGINAL FIRST THUNK: %x\n", (ctx->import_descriptors + i)->DUMMYUNINAME.i_original_first_thunk);
        printf("NAME: %d\n", (ctx->import_descriptors + i)->i_name);
        printf("FORWARDER CHAIN: %d\n", (ctx->import_descriptors + i)->i_forwarder_chain);
        printf("TIME DATE STAMP: %d\n", (ctx->import_descriptors + i)->i_time_date_stamp);
        printf("FIRST THUNK: %d\n\n", (ctx->import_descriptors + i)->i_first_thunk);
    }
}

void print_import_function_iat(i_pe_ctx* ctx)
{
    if(ctx == NULL)exit(1);
    for(size_t i = 0; i < ctx->import_desc_len; i++){
        struct i_pe_function_table* ftbl = ctx->function_table + i;
        if(ftbl == NULL)exit(1);
        printf("%s\n", ftbl->i_pe_dll_name);
        printf("TOTAL FUNCTIONS: %d\n", ftbl->i_pe_iat_len);

        if(ftbl->i_is_ordinal){
            for(size_t j = 0; j < ftbl->i_pe_iat_len; j++){
                if(ctx->is32bit(ctx)){
                    printf("ORDINAL: %08x\n", ftbl->i_data.i_data32[j].i_thunk_data32.i_address_of_data);
                } else {
                    printf("ORDINAL: %08lx\n", ftbl->i_data.i_data64[j].i_thunk_data64.i_address_of_data);
                }
            }
        } else {
            for(size_t j = 0; j < ftbl->i_pe_iat_len; j++){
                if(ctx->is32bit(ctx)){
                    printf("RVA: %08x", ftbl->i_data.i_data32[j].i_thunk_data32.i_address_of_data);
                } else{
                    printf("RVA: %08lx", ftbl->i_data.i_data64[j].i_thunk_data64.i_address_of_data);
                }
                printf("\t%s\n", ftbl->i_rep.i_function[j]);
            }
        }
        printf("\n");
    }
}
