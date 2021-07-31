#pragma once
#include <unicorn/unicorn.h>
#include <vmprofiler.hpp>

namespace vm
{
    class emu_t
    {
      public:
        explicit emu_t( vm::ctx_t *vm_ctx );
        ~emu_t();

        bool init();
        bool get_trace( std::vector< vm::instrs::code_block_t > &code_blocks );

      private:
        uc_engine *uc_ctx;
    };
} // namespace vm