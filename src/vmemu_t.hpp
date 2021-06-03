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

namespace vm
{
    struct virt_instr_t
    {
        vm::handler::mnemonic_t mnemonic_t;
        std::uint8_t opcode; // aka vm handler idx...

        struct
        {
            bool has_imm;
            struct
            {
                std::uint8_t imm_size; // size in bits...
                union
                {
                    std::int64_t s;
                    std::uint64_t u;
                };
            } imm;
        } operand;
    };

    enum class jcc_type
    {
        none,
        branching,
        absolute
    };

    struct code_block_t
    {
        struct
        {
            bool has_jcc;
            jcc_type type;
            std::uint32_t branch_rva[ 2 ];
        } jcc;

        std::vector< virt_instr_t > vinstrs;
    };

    class emu_t
    {
        using callback_t = std::function< void( uc_engine *, uint64_t, uint32_t, void * ) >;

      public:
        explicit emu_t( std::uint32_t vm_entry_rva, std::uintptr_t image_base, std::uintptr_t module_base );
        ~emu_t();

        bool init();
        bool get_trace( std::vector< vmp2::v2::entry_t > &entries );

      private:
        uc_err create_entry( vmp2::v2::entry_t *entry );
        static void hook_code( uc_engine *uc, uint64_t address, uint32_t size, vm::emu_t *obj );
        static bool hook_mem_invalid( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                                      vm::emu_t *obj );

        uc_engine *uc;
        uc_hook trace, trace1;

        std::uintptr_t image_base, module_base;
        std::uint32_t vm_entry_rva;

        zydis_routine_t vm_entry;
        std::uintptr_t *vm_handler_table;
        std::vector< vm::handler::handler_t > vm_handlers;
        std::vector< vmp2::v2::entry_t > *trace_entries;
    };
} // namespace vm