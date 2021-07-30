#pragma once
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
    };
} // namespace vm