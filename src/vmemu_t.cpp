#include "vmemu_t.hpp"

namespace vm
{
    emu_t::emu_t( vm::ctx_t *vmctx )
    {
    }

    emu_t::~emu_t()
    {
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