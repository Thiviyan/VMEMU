#include <unpacker.hpp>

namespace engine
{
    unpack_t::unpack_t( const std::vector< std::uint8_t > &packed_bin )
        : bin( packed_bin ), uc_ctx( nullptr ), heap_offset( 0ull ), pack_section_offset( 0ull )
    {
        win_img = reinterpret_cast< win::image_t<> * >( bin.data() );
        img_base = win_img->get_nt_headers()->optional_header.image_base;
        img_size = win_img->get_nt_headers()->optional_header.size_image;
        std::printf( "> image base = 0x%p, image size = 0x%x\n", img_base, img_size );
    }

    unpack_t::~unpack_t( void )
    {
        if ( uc_ctx )
            uc_close( uc_ctx );

        for ( auto &ptr : uc_hooks )
            if ( ptr )
                delete ptr;
    }

    bool unpack_t::init( void )
    {
        uc_err err;
        if ( ( err = uc_open( UC_ARCH_X86, UC_MODE_64, &uc_ctx ) ) )
        {
            std::printf( "> uc_open err = %d\n", err );
            return false;
        }

        if ( ( err = uc_mem_map( uc_ctx, IAT_VECTOR_TABLE, PAGE_4KB, UC_PROT_ALL ) ) )
        {
            std::printf( "> uc_mem_map iat vector table err = %d\n", err );
            return false;
        }

        if ( ( err = uc_mem_map( uc_ctx, STACK_BASE, STACK_SIZE, UC_PROT_ALL ) ) )
        {
            std::printf( "> uc_mem_map stack err, reason = %d\n", err );
            return false;
        }

        if ( ( err = uc_mem_map( uc_ctx, img_base, img_size, UC_PROT_ALL ) ) )
        {
            std::printf( "> map memory failed, reason = %d\n", err );
            return false;
        }

        // init iat vector table full of 'ret' instructions...
        auto c3_page = malloc( PAGE_4KB );
        {
            memset( c3_page, 0xC3, PAGE_4KB );

            if ( ( err = uc_mem_write( uc_ctx, IAT_VECTOR_TABLE, c3_page, PAGE_4KB ) ) )
            {
                std::printf( "> failed to init iat vector table...\n" );
                free( c3_page );
                return false;
            }
        }
        free( c3_page );

        map_bin.resize( img_size );
        memcpy( map_bin.data(), bin.data(), // copies pe headers (includes section headers)
                win_img->get_nt_headers()->optional_header.size_headers );

        win::section_header_t *sec_begin = win_img->get_nt_headers()->get_sections(),
                              *sec_end = sec_begin + win_img->get_nt_headers()->file_header.num_sections;

        std::for_each( sec_begin, sec_end, [ & ]( const win::section_header_t &sec_header ) {
            memcpy( map_bin.data() + sec_header.virtual_address, bin.data() + sec_header.ptr_raw_data,
                    sec_header.size_raw_data );
        } );

        auto basereloc_dir = win_img->get_directory( win::directory_id::directory_entry_basereloc );
        auto reloc_dir = reinterpret_cast< win::reloc_directory_t * >( basereloc_dir->rva + map_bin.data() );
        win::reloc_block_t *reloc_block = &reloc_dir->first_block;

        // apply relocations to all sections...
        while ( reloc_block->base_rva && reloc_block->size_block )
        {
            std::for_each( reloc_block->begin(), reloc_block->end(), [ & ]( win::reloc_entry_t &entry ) {
                switch ( entry.type )
                {
                case win::reloc_type_id::rel_based_dir64:
                {
                    auto reloc_at =
                        reinterpret_cast< std::uintptr_t * >( entry.offset + reloc_block->base_rva + map_bin.data() );

                    *reloc_at = img_base + ( ( *reloc_at ) - img_base );
                    break;
                }
                default:
                    break;
                }
            } );

            reloc_block = reloc_block->next();
        }

        // iat hook specific function...
        for ( auto import_dir = reinterpret_cast< win::import_directory_t * >(
                  win_img->get_directory( win::directory_id::directory_entry_import )->rva + map_bin.data() );
              import_dir->rva_name; ++import_dir )
        {
            for ( auto iat_thunk =
                      reinterpret_cast< win::image_thunk_data_t<> * >( import_dir->rva_first_thunk + map_bin.data() );
                  iat_thunk->address; ++iat_thunk )
            {
                if ( iat_thunk->is_ordinal )
                    continue;

                auto iat_name = reinterpret_cast< win::image_named_import_t * >( iat_thunk->address + map_bin.data() );

                if ( iat_hooks.find( iat_name->name ) != iat_hooks.end() )
                    iat_thunk->function = iat_hooks[ iat_name->name ].first + IAT_VECTOR_TABLE;
            }
        }

        // map the entire map buffer into unicorn-engine since we have set everything else up...
        if ( ( err = uc_mem_write( uc_ctx, img_base, map_bin.data(), map_bin.size() ) ) )
        {
            std::printf( "> failed to write memory... reason = %d\n", err );
            return false;
        }

        // setup unicorn-engine hooks on IAT vector table, sections with 0 raw size/ptr, and an invalid memory
        // handler...

        uc_hooks.push_back( new uc_hook );
        if ( ( err = uc_hook_add( uc_ctx, uc_hooks.back(), UC_HOOK_CODE, &engine::unpack_t::iat_dispatcher, this,
                                  IAT_VECTOR_TABLE, IAT_VECTOR_TABLE + PAGE_4KB ) ) )
        {
            std::printf( "> uc_hook_add error, reason = %d\n", err );
            return false;
        }

        uc_hooks.push_back( new uc_hook );
        if ( ( err = uc_hook_add( uc_ctx, uc_hooks.back(),
                                  UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED |
                                      UC_HOOK_INSN_INVALID,
                                  &engine::unpack_t::invalid_mem, this, true, false ) ) )
        {
            std::printf( "> uc_hook_add error, reason = %d\n", err );
            return false;
        }

        // execution break points on all sections that are executable but have no physical size on disk...
        std::for_each( sec_begin, sec_end, [ & ]( win::section_header_t &header ) {
            if ( !header.ptr_raw_data && !header.size_raw_data && header.characteristics.mem_execute &&
                 header.characteristics.mem_write && !header.is_discardable() )
            {
                uc_hooks.push_back( new uc_hook );
                if ( ( err = uc_hook_add( uc_ctx, uc_hooks.back(), UC_HOOK_CODE | UC_HOOK_MEM_WRITE,
                                          &engine::unpack_t::unpack_section_callback, this,
                                          header.virtual_address + img_base,
                                          header.virtual_address + header.virtual_size + img_base ) ) )
                {
                    std::printf( "> failed to add hook... reason = %d\n", err );
                    return false;
                }

                pack_section_offset = header.virtual_address + header.virtual_size;
            }
            else if ( header.characteristics.mem_execute )
            {
                uc_hooks.push_back( new uc_hook );
                if ( ( err = uc_hook_add( uc_ctx, uc_hooks.back(), UC_HOOK_CODE, &engine::unpack_t::code_exec_callback,
                                          this, header.virtual_address + img_base,
                                          header.virtual_address + header.virtual_size + img_base ) ) )
                {
                    std::printf( "> failed to add hook... reason = %d\n", err );
                    return false;
                }
            }
        } );

        return true;
    }

    bool unpack_t::unpack( std::vector< std::uint8_t > &output )
    {
        uc_err err;
        auto nt_headers = win_img->get_nt_headers();
        std::uintptr_t rip = nt_headers->optional_header.entry_point + img_base, rsp = STACK_BASE + STACK_SIZE;

        if ( ( err = uc_reg_write( uc_ctx, UC_X86_REG_RSP, &rsp ) ) )
        {
            std::printf( "> uc_reg_write error, reason = %d\n", err );
            return false;
        }

        if ( ( err = uc_reg_write( uc_ctx, UC_X86_REG_RIP, &rip ) ) )
        {
            std::printf( "> uc_reg_write error, reason = %d\n", err );
            return false;
        }

        std::printf( "> beginning execution at = 0x%p\n", rip );

        if ( ( err = uc_emu_start( uc_ctx, rip, 0ull, 0ull, 0ull ) ) )
        {
            std::printf( "> error starting emu... reason = %d\n", err );
            return false;
        }

        output.resize( img_size );
        if ( ( err = uc_mem_read( uc_ctx, img_base, output.data(), output.size() ) ) )
        {
            std::printf( "> uc_mem_read failed... err = %d\n", err );
            return false;
        }

        auto img = reinterpret_cast< win::image_t<> * >( output.data() );
        auto sections = img->get_nt_headers()->get_sections();
        auto section_cnt = img->get_file_header()->num_sections;

        std::for_each( sections, sections + section_cnt, [ & ]( win::section_header_t &header ) {
            if ( header.characteristics.mem_execute && !header.ptr_raw_data && !header.size_raw_data )
            {
                auto result = output.data() + header.virtual_address;
                std::vector< std::uintptr_t > reloc_rvas;

                do
                {
                    result = reinterpret_cast< std::uint8_t * >( xtils::um_t::get_instance()->sigscan(
                        result, header.virtual_size, MOV_RAX_0_SIG, MOV_RAX_0_MASK ) );

                    // offset from section begin...
                    auto reloc_offset = ( reinterpret_cast< std::uintptr_t >( result ) + 2 ) -
                                        reinterpret_cast< std::uintptr_t >( output.data() + header.virtual_address );

                    reloc_rvas.push_back( reloc_offset );
                } while ( result );

                auto basereloc_dir = img->get_directory( win::directory_id::directory_entry_basereloc );
                auto reloc_dir = reinterpret_cast< win::reloc_directory_t * >( basereloc_dir->rva + output.data() );
                win::reloc_block_t *reloc_block = &reloc_dir->first_block;

                //
                // assuming that the .reloc section is the last section in the entire module...
                //

                while ( reloc_block->base_rva && reloc_block->size_block )
                    reloc_block = reloc_block->next();

                reloc_block->base_rva = header.virtual_address;
                reloc_block->size_block = reloc_rvas.size() * sizeof win::reloc_entry_t;
            }

            header.ptr_raw_data = header.virtual_address;
            header.size_raw_data = header.virtual_size;
        } );
        return true;
    }

    void unpack_t::alloc_pool_hook( uc_engine *uc_ctx, unpack_t *obj )
    {
        uc_err err;
        std::uintptr_t rax, rdx;

        if ( ( err = uc_reg_read( uc_ctx, UC_X86_REG_RDX, &rdx ) ) )
        {
            std::printf( "> failed to read RDX... reason = %d\n", rdx );
            return;
        }

        auto size = ( ( rdx + PAGE_4KB ) & ~0xFFFull );
        if ( ( err = uc_mem_map( uc_ctx, HEAP_BASE + obj->heap_offset, size, UC_PROT_ALL ) ) )
        {
            std::printf( "> failed to allocate memory... reason = %d\n", err );
            return;
        }

        rax = HEAP_BASE + obj->heap_offset;
        obj->heap_offset += size;

        if ( ( err = uc_reg_write( uc_ctx, UC_X86_REG_RAX, &rax ) ) )
        {
            std::printf( "> failed to write rax... reason = %d\n", err );
            return;
        }
    }

    void unpack_t::free_pool_hook( uc_engine *uc_ctx, unpack_t *obj )
    {
        // TODO
    }

    void unpack_t::local_alloc_hook( uc_engine *uc_ctx, unpack_t *obj )
    {
        uc_err err;
        std::uintptr_t rax, rdx;

        if ( ( err = uc_reg_read( uc_ctx, UC_X86_REG_RDX, &rdx ) ) )
        {
            std::printf( "> failed to read RDX... reason = %d\n", rdx );
            return;
        }

        auto size = ( ( rdx + PAGE_4KB ) & ~0xFFFull );
        if ( ( err = uc_mem_map( uc_ctx, HEAP_BASE + obj->heap_offset, size, UC_PROT_ALL ) ) )
        {
            std::printf( "> failed to allocate memory... reason = %d\n", err );
            return;
        }

        rax = HEAP_BASE + obj->heap_offset;
        obj->heap_offset += size;

        if ( ( err = uc_reg_write( uc_ctx, UC_X86_REG_RAX, &rax ) ) )
        {
            std::printf( "> failed to write rax... reason = %d\n", err );
            return;
        }
    }

    void unpack_t::local_free_hook( uc_engine *uc_ctx, unpack_t *obj )
    {
        uc_err err;
        std::uintptr_t rax = 0ull;

        if ( ( err = uc_reg_write( uc_ctx, UC_X86_REG_RAX, &rax ) ) )
        {
            std::printf( "> failed to write rax... reason = %d\n", err );
            return;
        }
    }

    void unpack_t::load_library_hook( uc_engine *uc_ctx, unpack_t *obj )
    {
        uc_err err;
        std::uintptr_t rcx = 0ull;

        if ( ( err = uc_reg_read( uc_ctx, UC_X86_REG_RCX, &rcx ) ) )
        {
            std::printf( "> uc_reg_read error, reason = %d\n", err );
            return;
        }

        char buff[ 256 ];
        uc_strcpy( uc_ctx, buff, rcx );
        std::printf( "> LoadLibraryA(\"%s\")\n", buff );

        auto module_base = reinterpret_cast< std::uintptr_t >( LoadLibraryA( buff ) );

        auto module_size =
            reinterpret_cast< win::image_t<> * >( module_base )->get_nt_headers()->optional_header.size_image;

        if ( std::find( obj->loaded_modules.begin(), obj->loaded_modules.end(), module_base ) !=
             obj->loaded_modules.end() )
        {
            if ( ( err = uc_reg_write( uc_ctx, UC_X86_REG_RAX, &module_base ) ) )
            {
                std::printf( "> failed to set rax... reason = %d\n", err );
                return;
            }
        }
        else
        {
            if ( ( err = uc_mem_map( uc_ctx, module_base, module_size, UC_PROT_ALL ) ) )
            {
                std::printf( "> failed to load library... reason = %d\n", err );
                return;
            }

            if ( ( err = uc_mem_write( uc_ctx, module_base, reinterpret_cast< void * >( module_base ), module_size ) ) )
            {
                std::printf( "> failed to copy module into emulator... reason = %d\n", err );
                return;
            }

            if ( ( err = uc_reg_write( uc_ctx, UC_X86_REG_RAX, &module_base ) ) )
            {
                std::printf( "> failed to set rax... reason = %d\n", err );
                return;
            }

            obj->loaded_modules.push_back( module_base );
        }
    }

    void unpack_t::query_system_info_hook( uc_engine *uc_ctx, unpack_t *obj )
    {
        uc_err err;
        std::uintptr_t rcx, rdx, r8, r9;
        if ( ( err = uc_reg_read( uc_ctx, UC_X86_REG_RCX, &rcx ) ) )
        {
            std::printf( "> failed to read reg... reason = %d\n", err );
            return;
        }

        if ( ( err = uc_reg_read( uc_ctx, UC_X86_REG_RDX, &rdx ) ) )
        {
            std::printf( "> failed to read reg... reason = %d\n", err );
            return;
        }

        if ( ( err = uc_reg_read( uc_ctx, UC_X86_REG_R8, &r8 ) ) )
        {
            std::printf( "> failed to read reg... reason = %d\n", err );
            return;
        }

        if ( ( err = uc_reg_read( uc_ctx, UC_X86_REG_R9, &r9 ) ) )
        {
            std::printf( "> failed to read reg... reason = %d\n", err );
            return;
        }

        std::printf( "> rcx = 0x%p, rdx = 0x%p, r8 = 0x%p, r9 = 0x%p\n", rcx, rdx, r8, r9 );
    }

    void unpack_t::uc_strcpy( uc_engine *uc_ctx, char *buff, std::uintptr_t addr )
    {
        uc_err err;
        char i = 0u;
        auto idx = 0ul;

        do
        {
            if ( ( err = uc_mem_read( uc_ctx, addr + idx, &i, sizeof i ) ) )
                break;

        } while ( ( buff[ idx++ ] = i ) );
    }

    bool unpack_t::iat_dispatcher( uc_engine *uc, uint64_t address, uint32_t size, unpack_t *unpack )
    {
        auto vec = address - IAT_VECTOR_TABLE;
        for ( auto &[ iat_name, iat_hook_data ] : unpack->iat_hooks )
        {
            if ( iat_hook_data.first == vec )
            {
                std::printf( "> hooking import = %s\n", iat_name.c_str() );
                iat_hook_data.second( uc, unpack );
                return true;
            }
        }
        return false;
    }

    bool unpack_t::code_exec_callback( uc_engine *uc, uint64_t address, uint32_t size, unpack_t *unpack )
    {
        static ZydisDecoder decoder;
        static ZydisFormatter formatter;
        static ZydisDecodedInstruction instr;

        if ( static std::atomic< bool > once{ false }; !once.exchange( true ) )
        {
            ZydisDecoderInit( &decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64 );
            ZydisFormatterInit( &formatter, ZYDIS_FORMATTER_STYLE_INTEL );
        }

        auto instr_ptr = reinterpret_cast< void * >( unpack->map_bin.data() + ( address - unpack->img_base ) );
        if ( ZYAN_SUCCESS( ZydisDecoderDecodeBuffer( &decoder, instr_ptr, PAGE_4KB, &instr ) ) )
        {
            if ( instr.mnemonic == ZYDIS_MNEMONIC_CALL && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RAX )
            {
                std::uintptr_t rax = 0u, rip = 0u;
                uc_reg_read( uc, UC_X86_REG_RAX, &rax );
                uc_reg_read( uc, UC_X86_REG_RIP, &rip );

                if ( rax > unpack->img_base + unpack->img_size ) // skip calls to kernel32.dll...
                {
                    rip += instr.length;
                    uc_reg_write( uc, UC_X86_REG_RIP, &rip );
                }
            }
        }

        return true;
    }

    bool unpack_t::unpack_section_callback( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                                            unpack_t *unpack )
    {
        if ( address == unpack->pack_section_offset + unpack->img_base )
        {
            std::printf( "> dumping...\n" );
            uc_emu_stop( uc );
            return false;
        }
        return true;
    }

    void unpack_t::invalid_mem( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                                unpack_t *unpack )
    {
        switch ( type )
        {
        case UC_MEM_READ_UNMAPPED:
            std::printf( ">>> reading invalid memory at address = 0x%p, size = 0x%x\n", address, size );
            break;
        case UC_MEM_WRITE_UNMAPPED:
            std::printf( ">>> writing invalid memory at address = 0x%p, size = 0x%x, val = 0x%x\n", address, size,
                         value );
            break;
        case UC_MEM_FETCH_UNMAPPED:
        {
            std::printf( ">>> fetching invalid instructions at address = 0x%p\n", address );
            break;
        }
        default:
            break;
        }
    }
} // namespace engine