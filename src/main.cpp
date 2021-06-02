#include <cli-parser.hpp>
#include <fstream>
#include <iostream>
#include <unicorn/unicorn.h>
#include <xtils.hpp>

#include "vmemu_t.hpp"

int __cdecl main( int argc, const char *argv[] )
{
    argparse::argument_parser_t parser( "VMEmu", "VMProtect 2 Static VM Handler Emulator" );

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
    const auto module_base = reinterpret_cast< std::uintptr_t >(
        LoadLibraryExA( parser.get< std::string >( "vmpbin" ).c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES ) );

    zydis_routine_t vm_entry, calc_jmp;
    if ( !vm::util::flatten( vm_entry, vm_entry_rva + module_base ) )
    {
        std::printf( "> failed to flatten vm entry...\n" );
        return -1;
    }

    vm::util::deobfuscate( vm_entry );
    std::printf( "> flattened vm entry...\n" );
    std::printf( "> deobfuscated vm entry...\n" );
    std::printf( "==================================================================================\n" );
    vm::util::print( vm_entry );

    if ( !vm::calc_jmp::get( vm_entry, calc_jmp ) )
    {
        std::printf( "> failed to get calc_jmp...\n" );
        return -1;
    }

    vm::util::deobfuscate( calc_jmp );
    std::printf( "> calc_jmp extracted from vm_entry... calc_jmp:\n" );
    std::printf( "==================================================================================\n" );
    vm::util::print( calc_jmp );

    const auto advancment = vm::calc_jmp::get_advancement( calc_jmp );

    if ( !advancment.has_value() )
    {
        std::printf( "> failed to determine advancment...\n" );
        return -1;
    }

    std::vector< vmp2::v2::entry_t > entries;
    vm::emu_t emu( vm_entry_rva, image_base, module_base );

    if ( !emu.init() )
    {
        std::printf( "[!] failed to init emulator...\n" );
        return -1;
    }

    if ( !emu.get_trace( entries ) )
        std::printf( "[!] something failed during tracing, review the console for more information...\n" );

    std::printf( "> creating trace file...\n" );
    std::printf( "> finished tracing... number of virtual instructions = %d\n", entries.size() );
    std::ofstream output( parser.get< std::string >( "out" ), std::ios::binary );

    vmp2::v2::file_header file_header;
    memcpy( &file_header.magic, "VMP2", sizeof( "VMP2" ) - 1 );

    file_header.epoch_time = time( nullptr );
    file_header.entry_offset = sizeof file_header + NT_HEADER( module_base )->OptionalHeader.SizeOfImage;
    file_header.entry_count = entries.size();
    file_header.advancement = advancment.value();
    file_header.image_base = image_base;
    file_header.vm_entry_rva = vm_entry_rva;

    file_header.version = vmp2::version_t::v2;
    file_header.module_base = module_base;
    file_header.module_offset = sizeof file_header;
    file_header.module_size = umtils->image_size( parser.get< std::string >( "vmpbin" ).c_str() );

    output.write( reinterpret_cast< const char * >( &file_header ), sizeof file_header );
    output.write( reinterpret_cast< const char * >( module_base ), file_header.module_size );

    for ( auto &entry : entries )
        output.write( reinterpret_cast< const char * >( &entry ), sizeof entry );

    output.close();
    std::printf( "> finished writing trace to disk...\n" );
}
