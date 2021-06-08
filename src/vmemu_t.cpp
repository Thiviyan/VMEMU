#include "vmemu_t.hpp"

namespace vm
{
    emu_t::emu_t( vm::ctx_t *vmctx ) : uc( nullptr ), vmctx( vmctx )
    {
    }

    bool emu_t::init()
    {
        uc_err err;
        std::uintptr_t stack_base = 0x1000000;
        std::uintptr_t stack_addr = ( stack_base + ( 0x1000 * 20 ) ) - 0x6000;
        const auto rip = vmctx->module_base + vmctx->vm_entry_rva;

        if ( ( err = uc_open( UC_ARCH_X86, UC_MODE_64, &uc ) ) )
        {
            std::printf( "failed on uc_mem_map() with error returned %u: %s\n", err, uc_strerror( err ) );

            return false;
        }

        if ( ( err = uc_mem_map( uc, vmctx->module_base, vmctx->image_size, UC_PROT_ALL ) ) )
        {
            std::printf( "failed on uc_mem_map() with error returned %u: %s\n", err, uc_strerror( err ) );

            return false;
        }

        if ( ( err = uc_mem_map( uc, UC_STACK_ADDR, sizeof vm::cpu_ctx::stack, UC_PROT_ALL ) ) )
        {
            std::printf( "failed on uc_mem_map() with error returned %u: %s\n", err, uc_strerror( err ) );

            return false;
        }

        if ( ( err = uc_mem_write( uc, vmctx->module_base, reinterpret_cast< void * >( vmctx->module_base ),
                                   vmctx->image_size ) ) )
        {
            std::printf( "failed on uc_mem_write() with error returned %u: %s\n", err, uc_strerror( err ) );

            return false;
        }

        if ( ( err = uc_reg_write( uc, UC_X86_REG_RIP, &rip ) ) )
        {
            std::printf( "failed on uc_reg_write() with error returned %u: %s\n", err, uc_strerror( err ) );

            return false;
        }

        if ( ( err = uc_reg_write( uc, UC_X86_REG_RSP, &stack_addr ) ) )
        {
            std::printf( "failed on uc_reg_write() with error returned %u: %s\n", err, uc_strerror( err ) );

            return false;
        }

        if ( ( err = uc_hook_add( uc, &trace, UC_HOOK_CODE, &vm::emu_t::hook_code, this, vmctx->module_base,
                                  vmctx->module_base + vmctx->image_size ) ) )
        {
            std::printf( "failed on uc_hook_add() with error returned %u: %s\n", err, uc_strerror( err ) );

            return false;
        }

        if ( ( err = uc_hook_add( uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                                  vm::emu_t::hook_mem_invalid, this, 1, 0 ) ) )
        {
            std::printf( "failed on uc_hook_add() with error returned %u: %s\n", err, uc_strerror( err ) );

            return false;
        }
        return true;
    }

    emu_t::~emu_t()
    {
        if ( uc )
            uc_close( uc );
    }

    bool emu_t::get_trace( std::vector< vm::instrs::code_block_t > &entries )
    {
        uc_err err;
        code_blocks.push_back( { vm::instrs::code_block_t{ 0u }, {} } );

        if ( ( err = uc_emu_start( uc, vmctx->vm_entry_rva + vmctx->module_base, NULL, NULL, NULL ) ) )
        {
            std::printf( "failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror( err ) );

            for ( auto &[ code_block, uc_code_block_context ] : code_blocks )
                entries.push_back( code_block );

            return false;
        }

        static const auto _already_traced = [ & ]( std::uintptr_t code_block_addr ) -> bool {
            return std::find_if( code_blocks.begin(), code_blocks.end(), [ & ]( const auto code_block_data ) -> bool {
                       return code_block_data.first.vip_begin == code_block_addr ||
                              // sometimes the code block address is displaced by 1... and another byte for the
                              // opcode...
                              code_block_data.first.vip_begin == code_block_addr - 2 ||
                              code_block_data.first.vip_begin == code_block_addr - 1;
                   } ) != code_blocks.end();
        };

        static const auto _traced_all_paths =
            [ & ]( const std::vector< std::pair< vm::instrs::code_block_t, std::shared_ptr< cpu_ctx > > > &code_blocks )
            -> bool {
            return std::find_if(
                       code_blocks.begin(), code_blocks.end(),
                       []( const std::pair< vm::instrs::code_block_t, std::shared_ptr< cpu_ctx > > &code_block_data )
                           -> bool {
                           return code_block_data.first.jcc.has_jcc &&
                                  ( !_already_traced( code_block_data.first.jcc.block_addr[ 0 ] ) ||
                                    !_already_traced( code_block_data.first.jcc.block_addr[ 1 ] ) );
                       } ) == code_blocks.end();
        };

        static const auto _trace_branch = [ & ]( vm::instrs::code_block_t &code_block,
                                                 std::shared_ptr< cpu_ctx > &context,
                                                 std::uintptr_t branch_addr ) -> bool {
            if ( !context )
                return {};

            // restore context to virtual jmp... changing branch...
            uc_context_restore( uc, context->context );

            // restore entire stack....
            uc_mem_write( uc, UC_STACK_ADDR, context->stack, sizeof vm::cpu_ctx::stack );

            std::uintptr_t rip = 0u;
            uc_reg_read( uc, UC_X86_REG_RIP, &rip );

            // change the top qword on the stack to the branch rva...
            // the rva is image base'ed and only the bottom 32bits...
            std::uintptr_t branch_rva = ( ( branch_addr - vmctx->module_base ) + vmctx->image_base ) & 0xFFFFFFFFull;

            uc_mem_write( uc, code_block.vinstrs.back().trace_data.regs.rbp, &branch_rva, sizeof branch_rva );
            code_blocks.push_back( { vm::instrs::code_block_t{ 0u }, {} } );

            skip_current_jmp = true;
            if ( ( err = uc_emu_start( uc, rip, NULL, NULL, NULL ) ) )
            {
                std::printf( "failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror( err ) );
                return false;
            }
            return true;
        };

        while ( !_traced_all_paths( code_blocks ) )
        {
            for ( auto &[ code_block, uc_code_block_context ] : code_blocks )
            {
                if ( code_block.jcc.has_jcc )
                {
                    if ( !_already_traced( code_block.jcc.block_addr[ 0 ] ) )
                        _trace_branch( code_block, uc_code_block_context, code_block.jcc.block_addr[ 0 ] );

                    if ( !_already_traced( code_block.jcc.block_addr[ 1 ] ) )
                        _trace_branch( code_block, uc_code_block_context, code_block.jcc.block_addr[ 1 ] );
                }
            }
        }

        for ( auto &[ code_block, uc_code_block_context ] : code_blocks )
            entries.push_back( code_block );

        return true;
    }

    uc_err emu_t::create_entry( vmp2::v2::entry_t *entry )
    {
        uc_reg_read( uc, UC_X86_REG_R15, &entry->regs.r15 );
        uc_reg_read( uc, UC_X86_REG_R14, &entry->regs.r14 );
        uc_reg_read( uc, UC_X86_REG_R13, &entry->regs.r13 );
        uc_reg_read( uc, UC_X86_REG_R12, &entry->regs.r12 );
        uc_reg_read( uc, UC_X86_REG_R11, &entry->regs.r11 );
        uc_reg_read( uc, UC_X86_REG_R10, &entry->regs.r10 );
        uc_reg_read( uc, UC_X86_REG_R9, &entry->regs.r9 );
        uc_reg_read( uc, UC_X86_REG_R8, &entry->regs.r8 );
        uc_reg_read( uc, UC_X86_REG_RBP, &entry->regs.rbp );
        uc_reg_read( uc, UC_X86_REG_RDI, &entry->regs.rdi );
        uc_reg_read( uc, UC_X86_REG_RSI, &entry->regs.rsi );
        uc_reg_read( uc, UC_X86_REG_RDX, &entry->regs.rdx );
        uc_reg_read( uc, UC_X86_REG_RCX, &entry->regs.rcx );
        uc_reg_read( uc, UC_X86_REG_RBX, &entry->regs.rbx );
        uc_reg_read( uc, UC_X86_REG_RAX, &entry->regs.rax );
        uc_reg_read( uc, UC_X86_REG_EFLAGS, &entry->regs.rflags );

        entry->vip = entry->regs.rsi;
        entry->handler_idx = entry->regs.rax;
        entry->decrypt_key = entry->regs.rbx;

        uc_err err;
        if ( ( err = uc_mem_read( uc, entry->regs.rdi, entry->vregs.raw, sizeof entry->vregs.raw ) ) )
            return err;

        // copy virtual stack values...
        for ( auto idx = 0u; idx < sizeof( entry->vsp ) / 8; ++idx )
            if ( ( err = uc_mem_read( uc, entry->regs.rbp + ( idx * 8 ), &entry->vsp.qword[ idx ],
                                      sizeof entry->vsp.qword[ idx ] ) ) )
                return err;

        return UC_ERR_OK;
    }

    void emu_t::hook_code( uc_engine *uc, uint64_t address, uint32_t size, vm::emu_t *obj )
    {
        std::printf( ">>> Tracing instruction at 0x%p, instruction size = 0x%x\n", address, size );

        // bad code... but i need to skip JMP instructions when tracing branches since i save context
        // on the jmp instruction... so it needs to be skipped...
        if ( obj->skip_current_jmp )
        {
            obj->skip_current_jmp = false;
            return;
        }

        // grab JMP RDX/RCX <-- this register...
        static const auto jmp_reg = obj->vmctx->vm_entry[ obj->vmctx->vm_entry.size() ].instr.operands[ 0 ].reg.value;

        static ZydisDecoder decoder;
        static ZydisDecodedInstruction instr;
        static std::uintptr_t reg_val = 0u;

        // init zydis decoder only a single time...
        if ( static std::atomic< bool > once = true; once.exchange( false ) )
            ZydisDecoderInit( &decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64 );

        if ( ZYAN_SUCCESS(
                 ZydisDecoderDecodeBuffer( &decoder, reinterpret_cast< void * >( address ), size, &instr ) ) &&
             instr.mnemonic == ZYDIS_MNEMONIC_JMP && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
             instr.operands[ 0 ].reg.value == jmp_reg )
        {
            uc_err err;
            vmp2::v2::entry_t new_entry;
            std::optional< vm::instrs::virt_instr_t > virt_instr;
            vm::handler::profile_t *vm_handler_profile = nullptr;

            switch ( jmp_reg )
            {
            case ZYDIS_REGISTER_RDX:
                uc_reg_read( uc, UC_X86_REG_RDX, &reg_val );
                break;
            case ZYDIS_REGISTER_RCX:
                uc_reg_read( uc, UC_X86_REG_RCX, &reg_val );
                break;
            default:
                std::printf( "[!] invalid jump register... = %d\n", jmp_reg );
                exit( 0 );
            }

            // checks to see if the address
            // in JMP RDX/RCX is a vm handler address...
            static const auto vm_handler_check = [ & ]( const vm::handler::handler_t &vm_handler ) -> bool {
                return vm_handler.address == reg_val;
            };

            if ( std::find_if( obj->vmctx->vm_handlers.begin(), obj->vmctx->vm_handlers.end(), vm_handler_check ) ==
                 obj->vmctx->vm_handlers.end() )
                return;

            if ( ( err = obj->create_entry( &new_entry ) ) )
            {
                std::printf( "[!] failed to create new entry... reason = %u, %s\n", err, uc_strerror( err ) );

                exit( 0 );
            }

            if ( !obj->code_blocks.back().first.vip_begin )
                // -1 because the first byte is the opcode...
                obj->code_blocks.back().first.vip_begin = new_entry.vip - 1;

            if ( virt_instr = vm::instrs::get( *obj->vmctx, new_entry ); !virt_instr.has_value() )
            {
                std::printf( "[!] failed to create vm::instrs::virt_instr_t...\n" );

                exit( 0 );
            }

            obj->code_blocks.back().first.vinstrs.push_back( virt_instr.value() );

            // if there is a virtual JMP instruction then we need to grab jcc data for the current code_block_t
            // and then create a new code_block_t...
            if ( ( vm_handler_profile = obj->vmctx->vm_handlers[ new_entry.handler_idx ].profile ) &&
                 vm_handler_profile->mnemonic == vm::handler::mnemonic_t::JMP )
            {
                const auto code_block_address = vm::instrs::code_block_addr( *obj->vmctx, new_entry );
                auto jcc = vm::instrs::get_jcc_data( *obj->vmctx, obj->code_blocks.back().first );
                if ( jcc.has_value() )
                    obj->code_blocks.back().first.jcc = jcc.value();

                // save cpu state as well as stack...
                obj->code_blocks.back().second = std::make_shared< cpu_ctx >();

                if ( ( err = uc_context_alloc( uc, &obj->code_blocks.back().second->context ) ) )
                {
                    std::printf( "[!] failed to allocate context space...\n" );
                    exit( 0 );
                }

                if ( ( err = uc_context_save( uc, obj->code_blocks.back().second->context ) ) )
                {
                    std::printf( "[!] failed to save cpu context...\n" );
                    exit( 0 );
                }

                if ( ( err = uc_mem_read( uc, UC_STACK_ADDR, obj->code_blocks.back().second->stack,
                                          sizeof vm::cpu_ctx::stack ) ) )
                {
                    std::printf( "[!] failed to read stack into backup buffer...\n" );
                    exit( 0 );
                }

                // if the next code block has already been traced then stop emulation...
                if ( auto already_traced = std::find_if( obj->code_blocks.begin(), obj->code_blocks.end(),
                                                         [ & ]( const auto &code_block_data ) -> bool {
                                                             return code_block_data.first.vip_begin ==
                                                                    code_block_address;
                                                         } );
                     already_traced != obj->code_blocks.end() )
                {
                    uc_emu_stop( uc );
                }
                else // else set the next code block up...
                {
                    obj->code_blocks.push_back( { vm::instrs::code_block_t{ 0u }, {} } );
                }
            }
        }
        else if ( instr.mnemonic == ZYDIS_MNEMONIC_RET ) // finish tracing...
        {
            uc_emu_stop( uc );
            // vmexit's cannot have a branch...
            obj->code_blocks.back().first.jcc.has_jcc = false;
        }
    }

    bool emu_t::hook_mem_invalid( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                                  vm::emu_t *obj )
    {
        uc_err err;
        if ( ( err = uc_mem_map( obj->uc, address & ~0xFFFull, 0x1000, UC_PROT_ALL ) ) )
            std::printf( "failed on uc_mem_map() with error returned %u: %s\n", err, uc_strerror( err ) );

        switch ( type )
        {
        case UC_MEM_WRITE_UNMAPPED:
            printf( ">>> Missing memory is being WRITE at 0x%p, data size = %u, data value = 0x%p\n", address, size,
                    value );
            return true;
        case UC_MEM_READ_UNMAPPED:
            printf( ">>> Missing memory is being READ at 0x%p, data size = %u, data value = 0x%p\n", address, size,
                    value );
            return true;
        default:
            printf( ">>> Missing memory at 0x%p, data size = %u, data value = 0x%p\n", address, size, value );
            return true;
        }
    }
} // namespace vm