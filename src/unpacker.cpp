#include <unpacker.hpp>

namespace engine
{
    unpack_t::unpack_t( const std::vector< std::uint8_t > &packed_bin ) : bin( packed_bin ), uc_ctx( nullptr )
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

        // map sections...
        std::for_each( sec_begin, sec_end, [ & ]( const win::section_header_t &sec_header ) {
            memcpy( map_bin.data() + sec_header.virtual_address, bin.data() + sec_header.ptr_raw_data,
                    sec_header.size_raw_data );

            std::printf(
                "> mapped section = %s, virt address = 0x%p, virt size = 0x%x, phys offset = 0x%x, phys size = 0x%x\n",
                sec_header.name.to_string().data(), sec_header.virtual_address, sec_header.virtual_size,
                sec_header.ptr_raw_data, sec_header.size_raw_data );
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
            for ( auto iat_thunk = reinterpret_cast< win::image_thunk_data_t<> * >(
                      import_dir->rva_original_first_thunk + map_bin.data() );
                  iat_thunk->address; ++iat_thunk )
            {
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
                                  UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                                  &engine::unpack_t::invalid_mem, this, true, false ) ) )
        {
            std::printf( "> uc_hook_add error, reason = %d\n", err );
            return false;
        }

        // execution break points on all sections that are executable but have no physical size on disk...
        std::for_each( sec_begin, sec_end, [ & ]( win::section_header_t &header ) {
            if ( !header.ptr_raw_data && !header.size_raw_data && header.characteristics.mem_execute &&
                 !header.is_discardable() )
            {
                uc_hooks.push_back( new uc_hook );
                if ( ( err = uc_hook_add( uc_ctx, uc_hooks.back(), UC_HOOK_CODE,
                                          &engine::unpack_t::unpack_section_callback, this,
                                          header.virtual_address + img_base,
                                          header.virtual_address + header.virtual_size + img_base ) ) )
                {
                    std::printf( "> failed to add hook... reason = %d\n", err );
                    return false;
                }

                std::printf( "> adding unpack watch on section = %s\n", header.name.to_string().data() );
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

                std::printf( "> added execution callback on section = %s\n", header.name.to_string().data() );
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

        return true;
    }

    void unpack_t::alloc_pool_hook( uc_engine *uc_ctx )
    {
    }

    void unpack_t::free_pool_hook( uc_engine *uc_ctx )
    {
    }

    void unpack_t::local_alloc_hook( uc_engine *uc_ctx )
    {
    }

    void unpack_t::local_free_hook( uc_engine *uc_ctx )
    {
    }

    bool unpack_t::iat_dispatcher( uc_engine *uc, uint64_t address, uint32_t size, unpack_t *unpack )
    {
        auto vec = address - IAT_VECTOR_TABLE;
        for ( auto &[ iat_name, iat_hook_data ] : unpack->iat_hooks )
        {
            if ( iat_hook_data.first == vec )
            {
                std::printf( "> hooking import = %s\n", iat_name.c_str() );
                iat_hook_data.second( uc );
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
            char buffer[ 0x1000 ];
            ZydisFormatterFormatInstruction( &formatter, &instr, buffer, sizeof( buffer ), address );
            std::printf( "> 0x%p ", address );
            puts( buffer );
        }

        return true;
    }

    bool unpack_t::unpack_section_callback( uc_engine *uc, uint64_t address, uint32_t size, unpack_t *unpack )
    {
        std::printf( "> might be dump time...\n" );
        std::getchar();
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
            std::printf( ">>> fetching invalid instructions at address = 0x%p\n", address );
            break;
        default:
            break;
        }
    }
} // namespace engine