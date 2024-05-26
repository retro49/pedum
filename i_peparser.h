#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include "i_types.h"
#include "i_stream.h"

#ifndef I_DOS
#define I_DOS

#define I_DOS_MAGIC_M 'M'
#define I_DOS_MAGIC_Z 'Z'
#define I_DOS_MAGIC_MZ "MZ"
#define I_DOS_MAGIC 0x5a4d
#define I_DOS_END PE_MAGIC

#define DOS_HDR_SIZE (1<<6)
#define DOS_STUB_SIZE (1<<6)

// offsets in dos header
#define I_DOS_OFF_MAG 		0x00
#define I_DOS_OFF_CBLP 		0x02
#define I_DOS_OFF_CP 		0x04
#define I_DOS_OFF_CRLC 		0x06
#define I_DOS_OFF_CPARHDR 	0x08
#define I_DOS_OFF_MINALLOC 	0x0a
#define I_DOS_OFF_MAXALLOC 	0x0c
#define I_DOS_OFF_SS 		0x0e
#define I_DOS_OFF_SP 		0x10
#define I_DOS_OFF_CSUM 		0x12
#define I_DOS_OFF_IP 		0x14
#define I_DOS_OFF_CS 		0x16
#define I_DOS_OFF_LFARLC 	0x18
#define I_DOS_OFF_OVNO 		0x1A
#define I_DOS_OFF_RES 		0x1C

#define I_DOS_OFF_OEMID 		0x24
#define I_DOS_OFF_OEMINFO 	0x26
#define I_DOS_OFF_RES2 		0x28

#define PE_DOS_OFF_LFANEW 	0x3c

#ifdef ITYPES
#define DHDR_SIZE_WORD (sizeof(i16))
#else
#define DHDR_SIZE_WORD (sizeof(short))
#endif

typedef size_t dhoff;

struct i_dos_header{
	u16 i_e_magic;
	u16 i_e_cblp;
	u16 i_e_cp;
	u16 i_e_crlc;
	u16 i_e_cparhdr;
	u16 i_e_minalloc;
	u16 i_e_maxalloc;
	u16 i_e_ss;
	u16 i_e_sp;
	u16 i_e_csum;
	u16 i_e_ip;
	u16 i_e_cs;
	u16 i_e_lfarlc;
	u16 i_e_ovno;
	u16 i_e_res;

	u8 __padd0[DHDR_SIZE_WORD * 3];

	u16 i_e_oemid;
	u16 i_e_oeminfo;
	u16 i_e_res2;

	u8 __padd1[DHDR_SIZE_WORD * 9];

	u32 i_e_lfanew;
}__attribute__((__packed__));

#endif

#ifndef I_PE
#define I_PE

#ifndef I_PE_SIGNATURE
#define I_PE_SIGNATURE          0x00004550
#define I_PE_SIGNATURE_P        0x50
#define I_PE_SIGNATURE_E        0x45
#define I_PE_SIGNATURE_PE       "PE"
#endif

#ifndef I_PE_IMG_OPT_MAGIC
#define I_PE_IMG_OPT_MAGIC
#define I_PE_IMG_OPT_MAGIC_HDR32       0x10b
#define I_PE_IMG_OPT_MAGIC_HDR64       0x20b
#define I_PE_IMG_OPT_MAGIC_ROM         0x107
#endif

#ifndef I_PE_IMG_MACHINE
#define I_PE_IMG_MACHINE
#define I_PE_IMG_MACHINE_I386          0x014c
#define I_PE_IMG_MACHINE_IA64          0x0200
#define I_PE_IMG_MACHINE_AMD64         0x8664
#endif

#ifndef I_PE_IMG_OPT_SUBSYSTEM
#define I_PE_IMG_OPT_SUBSYSTEM
#define I_PE_IMG_OPT_SUBSYSTEM_UNKOWN                      0
#define I_PE_IMG_OPT_SUBSYSTEM_NATIVE                      1
#define I_PE_IMG_OPT_SUBSYSTEM_WINDOWS_GUI                 2
#define I_PE_IMG_OPT_SUBSYSTEM_WINDOWS_CUI                 3
#define I_PE_IMG_OPT_SUBSYSTEM_OS2_CUI                     5
#define I_PE_IMG_OPT_SUBSYSTEM_POSIX_CUI                   7
#define I_PE_IMG_OPT_SUBSYSTEM_WINDOWS_CE_GUI              9
#define I_PE_IMG_OPT_SUBSYSTEM_EFI_APPLICATION             10
#define I_PE_IMG_OPT_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER     11
#define I_PE_IMG_OPT_SUBSYSTEM_EFI_RUNTIME_DRIVER          12
#define I_PE_IMG_OPT_SUBSYSTEM_EFI_ROM                     13
#define I_PE_IMG_OPT_SUBSYSTEM_XBOX                        14
#define I_PE_IMG_OPT_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    16
#endif

#ifndef I_PE_IMG_OPT_DLLCHAR
#define I_PE_IMG_OPT_DLLCHAR
#define I_PE_IMG_OPT_DLLCHAR_HIGH_ENTROPY_VA        0x0020
#define I_PE_IMG_OPT_DLLCHAR_DYNAMIC_BASE           0x0040
#define I_PE_IMG_OPT_DLLCHAR_FORCE_INTEGRITY        0x0080
#define I_PE_IMG_OPT_DLLCHAR_NX_COMPAT              0x0100
#define I_PE_IMG_OPT_DLLCHAR_NO_ISOLATION           0x0200
#define I_PE_IMG_OPT_DLLCHAR_NO_SEH                 0x0400
#define I_PE_IMG_OPT_DLLCHAR_NO_BIND                0x0800
#define I_PE_IMG_OPT_DLLCHAR_APPCONTAINER           0x1000
#define I_PE_IMG_OPT_DLLCHAR_WDM_DIRVER             0x2000
#define I_PE_IMG_OPT_DLLCHAR_GUARD_CF               0x4000
#define I_PE_IMG_OPT_DLLCHAR_TERMINAL_SERVER_AWARE  0x8000
#endif

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 0x0010

#define IMAGE_SIZEOF_SHORT_NAME 8

static const char* I_PE_DATA_DIRECTORY_STRING[] = {
    "EXPORT DIRECTORY",
    "IMPORT DIRECTORY",
    "RESOURCE DIRECTORY",
    "EXCEPTION DIRECTORY",
    "SECURITY DIRECTORY",
    "BASE RELOCATION DIRECTORY",
    "DEBUG DIRECTORY",
    "DESCRIPTION DIRECTORY",
    "SPECIAL DIRECTORY",
    "THREAD LOCAL STORAGE DIRECTORY",
    "LOCAL CONFIGURATION DIRECTORY",
    "BOUND IMPORT DIRECTORY",
    "IMPORT ADDRESS TABLE DIRECTORY",
    "DELAY IMPORT DIRECTORY",
    "CLR RUNTIME DIRECTORY",
    "RESERVED DIRECTORY",
};


// pointed by first thunk
struct i_pe_thunk_data32 {
    union {
        u32 i_forawrder_string;
        u32 i_function;
        u32 i_ordinal;
        u32 i_address_of_data;
    }i_thunk_data32;
};

struct i_pe_thunk_data64 {
    union {
        u64 i_forawrder_string;
        u64 i_function;
        u64 i_ordinal;
        u64 i_address_of_data;
    }i_thunk_data64;
};

struct i_pe_function_table{
    i32 i_pe_dll_name_rva;
    i32 i_pe_iat_rva;
    i32 i_pe_iat_len;
    u8* i_pe_dll_name;

    union {
        struct i_pe_thunk_data32* i_data32;
        struct i_pe_thunk_data64* i_data64;
    }i_data;

    union{
        u8** i_function;
        u16* i_ordinal;
    }i_rep;
    bool i_is_ordinal;
    struct i_pe_import_descriptor* i_import_desc;
    void* ord_non_ord;
};


struct i_pe_import_descriptor{
    union {
        u32 i_characteristics;
        u32 i_original_first_thunk;
    }DUMMYUNINAME; // lookup table rva (ILT)
    u32 i_time_date_stamp;
    i32 i_forwarder_chain;
    u32 i_name;
    u32 i_first_thunk; // address table rva (IAT)
}__attribute__((__packed__));

// here we go for the section table
struct i_pe_section_table{
    u8 i_name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        u32 i_physical_address;
        u32 i_virtual_size;
    }phvi;
    u32 i_virtual_address;
    u32 i_size_of_raw_data;
    u32 i_pointer_to_raw_data;
    u32 i_pointer_to_relocations;
    u32 i_pointer_to_line_numbers;
    u16 i_number_of_relocations;
    u16 i_number_of_line_numbers;
    u32 i_characterstics;
}__attribute__((__packed__));

struct  i_pe_data_dir{
    u32 i_virtual_address;
    u32 i_size;
}__attribute__((__packed__));

union i_pe_image_base{
    u32 base32;
    u64 base64;
};

union i_pe_stack_reserve{
    u32 reserve32;
    u64 reserve64;
};

union i_pe_stack_commit{
    u32 commit32;
    u64 commit64;
};

union i_pe_heap_reserve{
    u32 reserve32; 
    u64 reserve64;
};

union i_pe_heap_commit{
    u32 commit32;
    u64 commit64;
};

struct i_pe_optional_header {
    u16 i_magic;
    u8 i_major_linker_version;
    u8 i_minor_linker_version;
    u32 i_sizeof_code;
    u32 i_sizeof_init_data;
    u32 i_sizeof_uninit_data;
    u32 i_addr_entry_point; /// entry point function address, relative to
                            /// the image base address
    u32 i_base_of_code;
    u32 i_base_of_data;
    union i_pe_image_base i_image_base;
    u32 i_section_alignment;
    u32 i_file_alignment;
    u16 i_major_operating_system_version;
    u16 i_minor_operating_system_version;
    u16 i_major_image_version;
    u16 i_minor_image_version;
    u16 i_major_subsystem_version;
    u16 i_minor_subsystem_version;
    u32 i_win32_version_value;
    u32 i_sizeof_image;
    u32 i_sizeof_headers;
    u32 i_checksum;
    u16 i_subsystem;
    u16 i_dll_characteristics;

    union i_pe_stack_reserve i_stack_reserve;
    union i_pe_stack_commit i_stack_commit;
    union i_pe_heap_reserve i_heap_reserve;
    union i_pe_heap_commit i_heap_commit;


    u32 i_loader_flags;
    u32 i_num_of_rva_and_sizes;
    struct i_pe_data_dir i_data_dir[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct i_pe_file_header{
    u16 i_machine; // machine architecture
    u16 i_nsections; // number of sections
    u32 i_time_date_stamp; // time date stamp
    u32 i_ptr_to_symbol_tbl; /// pointer to symbol table
                             ///
    u32 i_nsymbols; // number of symbols
    u16 i_sizeof_optional_hdr; // size of the optional header
    u16 i_characterstics; // characterstics
};


struct i_pe_nt_header{
    u32 i_signature; // magic (signature)
    struct i_pe_file_header i_file_header; // content of file image file header
    struct i_pe_optional_header i_opt_hdr;  // content of image optional header
                                          // how to represent the opt header for 32 or 64 bit architecture ?
};

typedef struct i_pe_ctx i_pe_ctx;

i_result i_dos_parser(i_pe_ctx*, i_fstream*); 
bool i_dos_is_dos_hdr(i_pe_ctx *);
bool i_dos_validate_dos_stream(i_fstream*);

bool i_pe_validate_pe_hdr(i_pe_ctx*);
i_result i_pe_parse_nt_hdr(i_pe_ctx*, i_fstream*);
i_result i_pe_parse_section_table(i_pe_ctx*, i_fstream*);
i_result i_pe_parse_import_descriptor(i_pe_ctx*, i_fstream*);

i_result i_pe_parse_import_address_table(i_pe_ctx*, i_fstream*);
i_result i_pe_parse_function_table(i_pe_ctx*, i_fstream*);
i_result i_pe_parse_functions(i_pe_ctx*, i_fstream*);

i64 i_pe_rva_to_offset(i_pe_ctx*, i64);
i64 i_pe_count_import_descriptor(i_pe_ctx*, i_fstream*);
i64 i_pe_count_import_address_table(i_pe_ctx*, i_fstream*, i64);

i_result i_ctx_parser(i_pe_ctx*, i_fstream*);
i_pe_ctx* i_pe_ctx_new(void);
bool i_pe_ctx_is32bit(i_pe_ctx*);
bool i_pe_ctx_is64bit(i_pe_ctx*);
void i_pe_ctx_free(i_pe_ctx*);
i64 i_util_readstr_len(i_fstream*, i64);
u8* i_util_readstr(i_fstream*, i64);
bool i_pe_validate_pe_strm(i_fstream*);

typedef i_result (*i_ctx_dos_parse)(i_pe_ctx*, i_fstream*);
typedef bool (*i_ctx_is_dos)(i_pe_ctx*);
typedef bool (*i_ctx_is_dos_strm)(i_fstream*);

typedef i_result (*i_ctx_pe_parse)(i_fstream*);
typedef i_result (*i_ctx_pe_parse_nt_hdr)(i_pe_ctx*, i_fstream*);
typedef i_result (*i_ctx_pe_parse_section_table)(i_pe_ctx*, i_fstream*);
typedef i_result (*i_ctx_pe_parse_import_descriptor)(i_pe_ctx*, i_fstream*);
typedef i_result (*i_ctx_pe_parse_function_table)(i_pe_ctx*, i_fstream*);
typedef i_result (*i_ctx_pe_parse_import_address_table)(i_pe_ctx*, i_fstream*);
typedef i_result (*i_ctx_pe_parse_functions)(i_pe_ctx*, i_fstream*);

typedef i64 (*i_ctx_pe_count_import_descriptor)(i_pe_ctx*, i_fstream*);
typedef i64 (*i_ctx_pe_rva_to_offset)(i_pe_ctx*, i64);
typedef i64 (*i_ctx_pe_count_import_address_table)(i_pe_ctx*, i_fstream*, i64);
typedef bool (*i_ctx_is64bit)(i_pe_ctx*);
typedef bool (*i_ctx_is32bit)(i_pe_ctx*);

typedef i_result(*i_ctx_parse)(i_pe_ctx*, i_fstream*);
typedef void (*i_ctx_free)(i_pe_ctx*);

struct i_pe_ctx{
#ifdef I_DOS
    struct i_dos_header* dos_header;
    i_ctx_dos_parse parse_dos_header;
    i_ctx_is_dos is_dos;
    i_ctx_is_dos_strm is_dos_strm;
#endif

#ifdef  I_PE
    struct i_pe_nt_header* nt_header;
    struct i_pe_section_table* section_tables;
    struct i_pe_import_descriptor* import_descriptors;
    struct  i_pe_function_table* function_table;
    size_t import_desc_len;
    size_t section_table_offset;

    i_ctx_pe_parse_nt_hdr parse_nt_header;
    i_ctx_pe_parse_section_table parse_section_table;
    i_ctx_pe_parse_import_descriptor parse_import_descriptor;
    i_ctx_pe_parse_import_address_table parse_import_address_table;
    i_ctx_pe_parse_function_table parse_function_table;
    i_ctx_pe_parse_functions parse_functions;

    i_ctx_pe_rva_to_offset rva_to_offset;
    i_ctx_pe_count_import_descriptor count_import_descriptor;
    i_ctx_pe_count_import_address_table count_import_address_table;
    i_ctx_is32bit is32bit;
    i_ctx_is64bit is64bit;
    i_ctx_parse ctx_parse;
    i_ctx_free ctx_free;
#endif
};


#endif
