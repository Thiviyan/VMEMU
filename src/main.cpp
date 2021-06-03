#include <cli-parser.hpp>
#include <fstream>
#include <iostream>
#include <unicorn/unicorn.h>
#include <xtils.hpp>

#include "vmemu_t.hpp"

int __cdecl main( int argc, const char *argv[] )
{
    argparse::argument_parser_t parser( "VMEmu", "VMProtect 2 VM Handler Emulator" );

    parser.add_argument()
        .name( "--vmentry" )
        .required( true )
        .description( "relative virtual address to a vm entry..." );

    parser.add_argument().name( "--vmpbin" ).required( true ).description( "path to unpacked virtualized binary..." );
    parser.add_argument().name( "--out" ).required( true ).description( "output file name for trace file..." );

    parser.enable_help();
    auto result = parser.parse( argc, argv );

    if ( result )
    {
        std::printf( "[!] error parsing commandline arguments... reason = %s\n", result.what().c_str() );
        return -1;
    }

    if ( parser.exists( "help" ) )
    {
        parser.print_help();
        return 0;
    }

    auto umtils = xtils::um_t::get_instance();
    const auto vm_entry_rva = std::strtoull( parser.get< std::string >( "vmentry" ).c_str(), nullptr, 16 );
    const auto image_base = umtils->image_base( parser.get< std::string >( "vmpbin" ).c_str() );
    const auto image_size = umtils->image_size( parser.get< std::string >( "vmpbin" ).c_str() );
    const auto module_base = reinterpret_cast< std::uintptr_t >(
        LoadLibraryExA( parser.get< std::string >( "vmpbin" ).c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES ) );

    std::printf( "> image base = %p, image size = %p, module base = %p\n", image_base, image_size, module_base );

    std::vector< vm::instrs::code_block_t > code_blocks;
    vm::ctx_t vmctx( module_base, image_base, image_size, vm_entry_rva );

    if ( !vmctx.init() )
    {
        std::printf( "[!] failed to init vmctx... this can be for many reasons..."
                     " try validating your vm entry rva... make sure the binary is unpacked and is"
                     "protected with VMProtect 2...\n" );
        return -1;
    }

    vm::emu_t emu( &vmctx );

    if ( !emu.init() )
    {
        std::printf( "[!] failed to init emulator...\n" );
        return -1;
    }

    if ( !emu.get_trace( code_blocks ) )
        std::printf( "[!] something failed during tracing, review the console for more information...\n" );

    std::printf( "> number of blocks = %d\n", code_blocks.size() );
    for ( auto &code_block : code_blocks )
    {
        std::printf( "> code block starts at = %p\n", code_block.vip_begin );
        std::printf( "> number of virtual instructions = %d\n", code_block.vinstrs.size() );
        std::printf( "> does this code block have a jcc? %s\n", code_block.jcc.has_jcc ? "yes" : "no" );

        if ( code_block.jcc.has_jcc )
            std::printf( "> branch 1 = %p, branch 2 = %p\n", code_block.jcc.block_addr[ 0 ],
                         code_block.jcc.block_addr[ 1 ] );
    }
}
