#pragma once
#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>

#include <atomic>
#include <fstream>
#include <functional>
#include <map>
#include <nt/image.hpp>
#include <vector>
#include <vmprofiler.hpp>

#define PAGE_4KB 0x1000
#define STACK_SIZE PAGE_4KB * 512

#define IAT_VECTOR_TABLE 0xFFFFF00000000000
#define STACK_BASE 0xFFFF000000000000
#define HEAP_BASE 0xFFF0000000000000

#define EX_ALLOCATE_POOL_VECTOR 0
#define EX_FREE_POOL_VECTOR 1
#define LOCAL_ALLOC_VECTOR 2
#define LOCAL_FREE_VECTOR 3
#define LOAD_LIBRARY_VECTOR 4
#define NT_QUERY_SYSTEM_INFO_VECTOR 5

#define MOV_RAX_0_SIG "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"
#define MOV_RAX_0_MASK "xxxxxxxxxx"

static_assert(sizeof MOV_RAX_0_SIG == sizeof MOV_RAX_0_MASK,
              "signature and mask sizes are wrong...");

namespace engine {
class unpack_t {
 public:
  explicit unpack_t(const std::vector<std::uint8_t> &bin);
  ~unpack_t(void);

  bool init(void);
  bool unpack(std::vector<std::uint8_t> &output);

 private:
  using iat_hook_t = std::function<void(uc_engine *, unpack_t *)>;

  uc_engine *uc_ctx;
  std::vector<uint8_t> bin, map_bin;
  std::vector<uc_hook *> uc_hooks;

  std::uintptr_t img_base, img_size, heap_offset, pack_section_offset;
  win::image_t<> *win_img;

  static void local_alloc_hook(uc_engine *, unpack_t *);
  static void local_free_hook(uc_engine *, unpack_t *);
  static void load_library_hook(uc_engine *, unpack_t *);
  static void uc_strcpy(uc_engine *, char *buff, std::uintptr_t addr);

  static bool iat_dispatcher(uc_engine *uc, uint64_t address, uint32_t size,
                             unpack_t *unpack);

  static bool unpack_section_callback(uc_engine *uc, uc_mem_type type,
                                      uint64_t address, int size, int64_t value,
                                      unpack_t *unpack);

  static bool code_exec_callback(uc_engine *uc, uint64_t address, uint32_t size,
                                 unpack_t *unpack);

  static void invalid_mem(uc_engine *uc, uc_mem_type type, uint64_t address,
                          int size, int64_t value, unpack_t *unpack);

  std::map<std::string, std::uintptr_t> loaded_modules;
  std::map<std::string, std::pair<std::uint32_t, iat_hook_t> > iat_hooks = {
      {"LocalAlloc", {LOCAL_ALLOC_VECTOR, &local_alloc_hook}},
      {"LocalFree", {LOCAL_FREE_VECTOR, &local_free_hook}},
      {"LoadLibraryA", {LOAD_LIBRARY_VECTOR, &load_library_hook}}};
};
}  // namespace engine