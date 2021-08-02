#include "vmemu_t.hpp"

namespace vm
{
    emu_t::emu_t( vm::ctx_t *vm_ctx ) : vm_ctx( vm_ctx ), uc_ctx( nullptr )
    {
    }

    emu_t::~emu_t()
    {
        if ( uc_ctx )
            uc_close( uc_ctx );
    }

    bool emu_t::init()
    {
        return {};
    }

    bool emu_t::get_trace( std::vector< vm::instrs::code_block_t > &entries )
    {
        return {};
    }
} // namespace vm