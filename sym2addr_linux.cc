#include "fuzz.h"
#include <sstream>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <regex>
#include <cstdlib>
#include <cstdio>
#include <set>
#include <string.h>
#include <string>
#include <unordered_map>
#include <utility>


static std::set<std::string> bins;


static std::map<sym_addr_t, sym_name_t> addr2sym;
static std::map<sym_info_t, unsigned long> sym2addr;

// todo: dynamic libc symbols for stuff like exit etc
// Strategy: Run objdump on the binary. Load the
unsigned long sym_to_addr(std::string bin, std::string name, int pid) {
    sym_info_t key {0, pid, bin, name};
    for (const auto & b : bins) {
        if (b.find(bin) != std::string::npos) {
            key.bin = b;
            break;
        }
    }
    if (sym2addr.find(key) != sym2addr.end()) {
        return sym2addr[key];
    }
    return 0UL;
}

const char* get_bin_full_path(std::string bin) {
    for (const auto & b : bins) {
        if (b.find(bin) != std::string::npos) {
            return b.c_str();
        }
    }
    return NULL;
}

sym_name_t addr_to_sym(unsigned long addr, int pid) {
    if (addr & (1UL << 63)) {
        // kernel address, we assume pid == 0
        pid = 0;
    }
    sym_addr_t key {addr, pid};
    if(addr2sym.find(key) != addr2sym.end())
        return addr2sym[key];
    for(int i =0; i<0x1000; i++){
        key.addr = addr - i;
        if(addr2sym.find(key) != addr2sym.end()){
            sym_name_t res = addr2sym[key];
            res.symbol += "+" + std::to_string(i);
            return res;
        }
    }
    return {"", ""};
}

void set_addr2sym(sym_info_t sym) {
    sym_addr_t addr_key{sym.addr, sym.pid};
    sym_name_t sym_key{sym.bin, sym.symbol};
    addr2sym[addr_key] = sym_key;
    
    // hacking: we also add an entry for pid==0
    addr_key.pid = 0;
    if (addr2sym.find(addr_key) == addr2sym.end()) {
        addr2sym[addr_key] = sym_key;
    }
}

void set_sym2addr(sym_info_t sym) {
    sym_info_t key {
        0,
        sym.pid,
        sym.bin,
        sym.symbol
    };
    key.addr = 0;
    sym2addr[key] = sym.addr;
    
    // hacking: we also add an entry for pid==0
    key.pid = 0;
    if (sym2addr.find(key) == sym2addr.end()) {
        sym2addr[key] = sym.addr;
    }
}

static std::string executeCommand(const char* cmd) {
    std::string result, line;
    char buf[1000];
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return result;
    while (fgets(buf, 1000, pipe) != nullptr) {
        result += std::string(buf);
    }
    pclose(pipe);
    return result;
}

// Function to parse the output of 'nm' command and construct map of addresses to symbol names
std::map<std::string, size_t> get_symbol_map(const std::string& binaryPath) {
    std::map<std::string, size_t> symbolMap;
    std::string nmOutput = executeCommand(("nm -n -C -a " + binaryPath + "| grep -e ' t ' -e ' T ' -e ' B ' -e ' D ' -e ' R '").c_str());
    size_t pos = 0;
    while ((pos = nmOutput.find("\n")) != std::string::npos) {
        std::string line = nmOutput.substr(0, pos);
        nmOutput.erase(0, pos + 1);
        size_t addrEnd = line.find(' ');
        size_t nameStart = line.find(' ', addrEnd + 1);
        if (addrEnd != std::string::npos && nameStart != std::string::npos) {
            std::string address = line.substr(0, addrEnd);
            std::string name = line.substr(nameStart + 1);
            symbolMap.emplace(name, strtoull(address.c_str(), NULL, 16));
        }
    }
    nmOutput = executeCommand(("nm -n -C -a -D " + binaryPath + "| grep -e ' t ' -e ' T ' -e ' B ' -e ' D ' -e ' R '").c_str());
    pos = 0;
    while ((pos = nmOutput.find("\n")) != std::string::npos) {
        std::string line = nmOutput.substr(0, pos);
        nmOutput.erase(0, pos + 1);
        size_t addrEnd = line.find(' ');
        size_t nameStart = line.find(' ', addrEnd + 1);
        if (addrEnd != std::string::npos && nameStart != std::string::npos) {
            std::string address = line.substr(0, addrEnd);
            std::string name = line.substr(nameStart + 1);
            symbolMap.emplace(name, strtoull(address.c_str(), NULL, 16));
        }
    }
    return symbolMap;
}

void load_symbol_map(char *path) {
    uint64_t start, size, sh_addr;
    std::string binfile, section; 
    int log = 0;
    std::ifstream file(path);
    std::string str; 
    std::stringstream ss;
    std::regex reg_regex("Symbolization Range: (\\w+) - (\\w+) size: (\\w+) file: ([^\\s]+) section: ([^\\s]+) sh_addr: (\\w+)");

    char linkpath[100];
    readlink("/proc/self/fd/1", linkpath, 100);
    linkpath[99] = 0;
    log = (strstr(linkpath, "fuzz-0.log") != NULL);

    printf(".loading symbolization ranges from %s\n", path);
    while (std::getline(file, str))
    {
        std::smatch match; 
        std::regex_search(str, match, reg_regex);
        if(match.size() < 1){
            printf("Unexpected line: %s\n", str.c_str());
            continue;
        }
        ss.clear();
        ss << std::hex << match[1].str(); 
        ss >> start;

        ss.clear();
        ss << std::hex << match[3].str(); 
        ss >> size;

        ss.clear();
        ss << std::hex << match[6].str();
        ss >> sh_addr;
    
        binfile = match[4].str();
        section = match[5].str();
        verbose_printf(":: loaded range: %s %s 0x%lx +0x%lx\n", binfile.c_str(), section.c_str(), start, size);
        bins.insert(binfile);
        if(section == ".text") {
            auto m = get_symbol_map(binfile);
            auto offset = start - sh_addr;
            for(auto it: m) {
                if(it.second) {
                    std::string name = it.first;
                    name.erase(std::find(name.begin(), name.end(), '('), name.end());
                    /* std::replace(name.begin(), name.end(), '(', '\0'); */
                    // addr2sym[it.second + offset].push_back(std::make_pair(binfile, name));
                    if(log)
                        printf(".info Symbol Name added: %s@%s %lx\n", name.c_str(), binfile.c_str(), it.second+offset);
                    // sym2addr[std::make_pair(binfile, name)] = it.second + offset;
                    // printf("Looking up %s@%s %lx\n", name.c_str(), binfile.c_str(), sym2addr[std::make_pair(binfile, name)]);
                    /* if(!sym2addr.emplace(std::make_pair(binfile, name), it.second + offset).second) */
                    /*     printf(".warning Symbol Name Collision: %s@%s %lx %lx\n", name.c_str(), binfile.c_str(), it.second+offset, sym2addr[std::make_pair(binfile, name)]); */
                }
            }
        }
    }
    printf("sym2addr: vmlinux, init_task %lx\n", sym_to_addr("vmlinux", "init_task"));
    printf("sym2addr: vmlinux, dump_stack %lx\n", sym_to_addr("vmlinux", "dump_stack"));
    printf("sym2addr: vmlinux, do_idle %lx\n", sym_to_addr("vmlinux", "do_idle"));
}

/* Assume the sqlite database specified by  has one table: addr2sym
    * addr2sym: addr, bin, name, pid
    * addr2sym: 0x7f8a4c3b0000, vmlinux, init_task, 0
    * addr2sym: 0x7f8a4c3b0000, vmlinux, dump_stack, 0
    * addr2sym: 0x7f8a4c3b0000, vmlinux, do_idle, 0
   construct addr2sym and sym2addr from this table
*/
void load_symbol_map_from_db(const char* path) {
    open_db(path);
    load_sym();
    for (const auto& sym : sym2addr){
        bins.insert(sym.first.bin);
    }
}
void load_symbol_map_from_kallsyms(const char* kallsyms_path) {
    load_kallsyms(kallsyms_path);
    for (const auto& sym : sym2addr){
        bins.insert(sym.first.bin);
    }
}
void load_symbol_map_from_maps(const char* maps_path) {
    char* symbols_dir = getenv("SYMBOLS_DIR");
    if (!symbols_dir) {
        return;
    }

    std::ifstream file(maps_path);
    if (!file.is_open()) {
        fprintf(stderr, "Failed to open maps file: %s\n", maps_path);
        return;
    }

    std::filesystem::path maps_file_path(maps_path);
    int pid = std::stoi(maps_file_path.stem().string());

    std::string line;
    unsigned long start, end, offset, inode;
    char perm[5];
    char dev[6];
    char path[256];
    char last_path[256] = {0};

    while (std::getline(file, line)) {
        int ret = sscanf(line.c_str(), "%lx-%lx %4s %lx %5s %lu %255[^\n]", &start, &end, perm, &offset, dev, &inode, path);
        if (ret < 7){
            continue; // Skip lines that do not match the expected format
        }
        if (inode == 0) {
            continue; // Skip lines with inode 0
        }
        if (!strcmp(path, last_path)) {
            continue; // Skip if the path is the same as the last one
        }

        // get the basename of the path
        std::string s_path = path;
        std::string basename = s_path.substr(s_path.find_last_of('/') + 1);
        if (basename.empty()) {
            basename = s_path; // If no '/' found, use the whole path
        }

        // check if $SYMBOLS_DIR/basename is a valid file
        std::string full_path = std::string(symbols_dir) + "/" + basename;
        if (access(full_path.c_str(), F_OK)) {
            continue;
        } 

        printf("loading symbols from %s\n", full_path.c_str());
        auto m = get_symbol_map(full_path);
        for (auto it : m) {
            if (it.second) {
                std::string name = it.first;
                name.erase(std::find(name.begin(), name.end(), '('), name.end());
                sym_info_t sym_info = {
                    it.second + start,
                    pid,
                    full_path,
                    name 
                };
                set_addr2sym(sym_info);
                set_sym2addr(sym_info);
            }
        }
        bins.insert(full_path);
        strcpy(last_path, path);
    }
}
void load_symbol_map_from_maps(int pid){
    std::string filename = std::to_string(pid) + "-maps";
    load_symbol_map_from_maps(filename.c_str());
}

void store_sym_back_to_db(const char* db_path){
    open_db(db_path);
    store_sym(sym2addr);
    printf("store_sym_back_to_db: stored %lu symbols\n", sym2addr.size());
}
