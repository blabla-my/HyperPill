#include "config.h"
#include <sqlite3.h>
#include <stdio.h>
#include <map>
#include "fuzz.h"
#include <vector>


sqlite3 *db;
void open_db(const char* path) {
    if (db) return;

    char *err_msg = 0;

    int rc = sqlite3_open(path, &db);

    if (rc != SQLITE_OK) {

        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);

        return;
    }

    const char *sql = "CREATE TABLE MMIO(Address INT, Length INT); "
                "CREATE TABLE PIO(Address INT, Length INT); "
                "CREATE TABLE SYM(Address INT, Bin TEXT, Symbol Text, Pid INT); ";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
}

void insert_mmio(uint64_t addr, uint64_t len){
    sqlite3_stmt *res;
    const char *sql = "INSERT INTO MMIO(Address, Length) VALUES (?, ?);";
    int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    sqlite3_bind_int64(res, 1, addr);
    sqlite3_bind_int64(res, 2, len);
    int step = sqlite3_step(res);
    sqlite3_finalize(res);
}

void insert_pio(uint16_t addr, uint16_t len){
    sqlite3_stmt *res;
    const char *sql = "INSERT INTO PIO(Address, Length) VALUES (?, ?);";
    int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    sqlite3_bind_int(res, 1, addr);
    sqlite3_bind_int(res, 2, len);
    int step = sqlite3_step(res);
    sqlite3_finalize(res);
}

void insert_sym(uint64_t addr, const char* bin, const char* sym, int pid){
    sqlite3_stmt *res;
    const char *sql = "INSERT INTO SYM(Address, Bin, Symbol, Pid) VALUES (?, ?, ?, ?);";
    int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    sqlite3_bind_int64(res, 1, addr);
    sqlite3_bind_text(res, 2, bin, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 3, sym, -1, SQLITE_STATIC);
    sqlite3_bind_int(res, 4, pid);
    int step = sqlite3_step(res);
    sqlite3_finalize(res);
}

void load_regions(std::map<uint16_t, uint16_t> &pio_regions, std::map<bx_address, uint32_t> &mmio_regions) {
    sqlite3_stmt *res;
    const char *sql = "SELECT Address, Length from PIO";
    int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    int step;
    while((step = sqlite3_step(res)) == SQLITE_ROW) {
        if(sqlite3_column_int64(res, 1)) {
            pio_regions[sqlite3_column_int64(res, 0)] = sqlite3_column_int64(res, 1);
            printf("Loaded PIO Region: %lx +%lx\n", 
                    sqlite3_column_int64(res, 0),
                    sqlite3_column_int64(res, 1));
        }
    }
    sql = "SELECT Address, Length from MMIO";
    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    while((step = sqlite3_step(res)) == SQLITE_ROW) {
        if(sqlite3_column_int64(res, 1)){
            printf("Loaded MMIO Region: %lx +%lx\n", 
                    sqlite3_column_int64(res, 0),
                    sqlite3_column_int64(res, 1));
            mmio_regions[sqlite3_column_int64(res, 0)] = sqlite3_column_int64(res, 1);
        }
    }
}

void load_kallsyms(const std::string& kallsyms_path) {
    FILE *fp = fopen(kallsyms_path.c_str(), "r");
    if (!fp) {
        perror("Failed to open kallsyms file");
        return;
    }

    // a line of kallsyms looks like: "ffffffffc0ed4fa0 t kvm_register_perf_callbacks  [kvm]"
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        size_t addr;
        char type;
        char sym[64];
        char mod[64];

        // Parse the line
        int ret = sscanf(line, "%lx %c %63s %63s", &addr, &type, sym, mod);
        if (ret == 3){
            // If the module is not specified, we assume it's the main binary
            snprintf(mod, sizeof(mod), "vmlinux");
        } else if (ret != 4) {
            fprintf(stderr, "Failed to parse line: %s", line);
            continue; 
        }

        // Store the symbol
        sym_info_t sym_info {
            addr,
            0, // pid is 0 for kernel symbols
            mod,
            sym
        };
        set_addr2sym(sym_info);
        set_sym2addr(sym_info);
    }
    
}

void load_sym() {
    sqlite3_stmt *res;
    const char *sql = "SELECT Address, Bin, Symbol, Pid from SYM";
    int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    int step;
    while((step = sqlite3_step(res)) == SQLITE_ROW) {
        if(sqlite3_column_int64(res, 0)){
            std::string bin = (const char*)sqlite3_column_text(res, 1);
            std::string sym = (const char*)sqlite3_column_text(res, 2);
            size_t addr = sqlite3_column_int64(res, 0);
            int pid = sqlite3_column_int(res, 3);
            
            sym_info_t sym_info {
                addr,
                pid,
                bin,
                sym
            };
            set_addr2sym(sym_info);
            set_sym2addr(sym_info);
        }
    }
    sqlite3_finalize(res);
}

void store_sym(const std::map<sym_info_t, unsigned long>& sym2addr) {
    for (auto it: sym2addr) {
        sym_info_t sym_info = it.first;
        unsigned long addr = it.second;
        // sym_info.show();
        insert_sym(addr, sym_info.bin.c_str(), sym_info.symbol.c_str(), sym_info.pid);
    }
}

std::vector<bx_address> select_sym(const char* sym) {
    std::vector<bx_address> result;
    sqlite3_stmt *res;
    const char *sql = "SELECT Address from SYM WHERE Symbol = ?";
    int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    sqlite3_bind_text(res, 1, sym, -1, SQLITE_STATIC);
    int step;
    while((step = sqlite3_step(res)) == SQLITE_ROW) {
        bx_address addr = sqlite3_column_int64(res, 0);
        result.push_back(addr);
    }
    sqlite3_finalize(res);
    return result;
}

std::vector<int> select_pid(const char* bin) {
    std::vector<int> result;
    sqlite3_stmt* res = nullptr;
    const char* sql = "SELECT DISTINCT Pid FROM SYM WHERE Bin = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &res, nullptr) == SQLITE_OK) {
        // Bind the parameter
        sqlite3_bind_text(res, 1, bin, -1, SQLITE_TRANSIENT);

        // Step through the rows
        while (sqlite3_step(res) == SQLITE_ROW) {
            int pid = sqlite3_column_int(res, 0);
            if (pid != 0) {
                printf("found pid %d\n", pid);
                result.push_back(pid);
            }
        }
    }

    // Finalize statement to avoid memory leak
    if (res) {
        sqlite3_finalize(res);
    }

    return result;
}
