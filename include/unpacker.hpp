#pragma once
#include <functional>
#include <unicorn/unicorn.h>

#include <Zydis/Zydis.h>
#include <atomic>
#include <fstream>
#include <map>
#include <nt/image.hpp>
#include <vector>

#define PAGE_4KB 0x1000
#define STACK_SIZE PAGE_4KB * 512

#define IAT_VECTOR_TABLE 0xFFFFF00000000000
#define STACK_BASE 0xFFFF000000000000
#define HEAP_BASE 0xFFF0000000000000

#define EX_ALLOCATE_POOL_VECTOR 0
#define EX_FREE_POOL_VECTOR 1
#define LOCAL_ALLOC_VECTOR 2
#define LOCAL_FREE_VECTOR 3
#define LOAD_LIBRARY_VECTOR 4

namespace engine
{
    class unpack_t
    {
      public:
        explicit unpack_t( const std::vector< std::uint8_t > &bin );
        ~unpack_t( void );

        bool init( void );
        bool unpack( std::vector< std::uint8_t > &output );

      private:
        using iat_hook_t = std::function< void( uc_engine *, unpack_t * ) >;

        uc_engine *uc_ctx;
        std::vector< uint8_t > bin, map_bin;
        std::vector< uc_hook * > uc_hooks;

        std::uintptr_t img_base, img_size, heap_offset, pack_section_offset;
        win::image_t<> *win_img;

        static void alloc_pool_hook( uc_engine *, unpack_t * );
        static void free_pool_hook( uc_engine *, unpack_t * );
        static void local_alloc_hook( uc_engine *, unpack_t * );
        static void local_free_hook( uc_engine *, unpack_t * );
        static void load_library_hook( uc_engine *, unpack_t * );
        static void uc_strcpy( uc_engine *, char *buff, std::uintptr_t addr );

        static bool iat_dispatcher( uc_engine *uc, uint64_t address, uint32_t size, unpack_t *unpack );
        static bool unpack_section_callback( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                                             unpack_t *unpack );

        static bool code_exec_callback( uc_engine *uc, uint64_t address, uint32_t size, unpack_t *unpack );
        static void invalid_mem( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                                 unpack_t *unpack );

        std::vector< std::uintptr_t > loaded_modules;
        std::map< std::string, std::pair< std::uint32_t, iat_hook_t > > iat_hooks = {
            { "ExAllocatePool", { EX_ALLOCATE_POOL_VECTOR, &alloc_pool_hook } },
            { "ExFreePool", { EX_FREE_POOL_VECTOR, &free_pool_hook } },
            { "LocalAlloc", { LOCAL_ALLOC_VECTOR, &local_alloc_hook } },
            { "LocalFree", { LOCAL_FREE_VECTOR, &local_free_hook } },
            { "LoadLibraryA", { LOAD_LIBRARY_VECTOR, &load_library_hook } } };
    };
} // namespace engine