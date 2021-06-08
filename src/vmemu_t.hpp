#pragma once
#include <Zydis/Zydis.h>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <unicorn/unicorn.h>
#include <vmp2.hpp>
#include <vmprofiler.hpp>
#include <xtils.hpp>

#define UC_STACK_ADDR 0x1000000

namespace vm
{
    struct cpu_ctx
    {
        uc_context *context;
        std::uint8_t stack[ PAGE_4K * 100 ];
    };

    class emu_t
    {
        using callback_t = std::function< void( uc_engine *, uint64_t, uint32_t, void * ) >;

      public:
        explicit emu_t( vm::ctx_t *vmctx );
        ~emu_t();

        bool init();
        bool get_trace( std::vector< vm::instrs::code_block_t > &entries );

      private:
        uc_err create_entry( vmp2::v2::entry_t *entry );
        static void hook_code( uc_engine *uc, uint64_t address, uint32_t size, vm::emu_t *obj );
        static bool hook_mem_invalid( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                                      vm::emu_t *obj );

        uc_engine *uc;
        uc_hook trace, trace1;

        bool skip_current_jmp;
        vm::ctx_t *vmctx;
        std::vector< std::pair< vm::instrs::code_block_t, std::shared_ptr<cpu_ctx> > > code_blocks;
    };
} // namespace vm