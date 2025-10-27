#include "bochs.h"
#include "config.h"
#include "cpu/cpu.h"
#include "fuzz.h"
#include "conveyor.h"

#include "virtio.h"
#include <cstdio>
#include <fstream>
#include <regex>


void load_manual_ranges(char* range_file, char* range_regex, std::map<uint16_t, uint16_t> &pio_regions, std::map<bx_address, uint32_t> &mmio_regions) {
    assert(range_file);
    assert(range_regex);
        
    std::regex rx(range_regex);

    std::ifstream infile(range_file);
    std::string line;
    while (std::getline(infile, line))
    {
        if (line.find("ram)") != std::string::npos) {
            continue;
        }
        if (line.find("rom)") != std::string::npos) {
            continue;
        }
        printf("MATCH: %s\n", line.c_str());
        std::istringstream iss(line);
        uint64_t start, end;
        char c;
        if (!(iss >> std::hex  >> start >> c >>  std::hex >> end)) { continue; } 
        if (c != '-') continue;;
        
        std::smatch match;
        bool to_fuzz = false;
        if(std::regex_search(line, match, rx)) {
            to_fuzz = true;
            if(start < 0x10000)
                pio_regions[start] = end-start;
            else
                add_mmio_region(start, end-start);
            printf("Will fuzz: %s\n", line.c_str());
        }

        if (line.find("virtio-pci-common") != std::string::npos) {
            // line will be "virtio-pci-common-virtio-xxx"
            // use regex to extract the device name
            std::regex dev_regex("virtio-pci-common-(.*)");
            std::smatch dev_match;
            if(std::regex_search(line, dev_match, dev_regex)){
                std::string dev_name = dev_match[1].str();
                printf("Found virtio device common cfg: %s, %lx - %lx\n", dev_name.c_str(), start, end);
                if (get_vqueue_manager().create_virtio_device(dev_name, to_fuzz))
                    get_vqueue_manager().add_config_space(dev_name, ConfigSpace::COMMON, start, end-start);
            }
        }
        if (line.find("virtio-pci-notify") != std::string::npos) {
            // line will be "virtio-pci-notify-virtio-xxx"
            // use regex to extract the device name
            std::regex dev_regex("virtio-pci-notify-(.*)");
            std::smatch dev_match;
            if(std::regex_search(line, dev_match, dev_regex)){
                std::string dev_name = dev_match[1].str();
                printf("Found virtio device notify cfg: %s, %lx - %lx\n", dev_name.c_str(), start, end);
                if (get_vqueue_manager().create_virtio_device(dev_name, to_fuzz))
                    get_vqueue_manager().add_config_space(dev_name, ConfigSpace::NOTIFY, start, end-start);
            }
        }
    }
    get_vqueue_manager().group_vrings_by_page();
}
