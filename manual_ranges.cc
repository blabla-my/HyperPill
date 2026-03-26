#include "bochs.h"
#include "config.h"
#include "cpu/cpu.h"
#include "fuzz.h"
#include "conveyor.h"

#include "option.h"
#include "virtio.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace {

const char *target_virtio_from_range_regex(const char *range_regex)
{
	if (!range_regex)
		return nullptr;
	if (strstr(range_regex, "virtio-scsi") != nullptr)
		return "virtio-scsi";
	if (strstr(range_regex, "virtio-net") != nullptr)
		return "virtio-net";
	return nullptr;
}

const char *lspci_match_string_for_target(const char *target_virtio)
{
	if (!target_virtio)
		return nullptr;
	if (strcmp(target_virtio, "virtio-scsi") == 0)
		return "Virtio 1.0 SCSI";
	if (strcmp(target_virtio, "virtio-net") == 0)
		return "Virtio network device";
	return nullptr;
}

bool line_is_blank(const std::string &line)
{
	return std::all_of(line.begin(), line.end(), [](unsigned char ch) {
		return std::isspace(ch) != 0;
	});
}

bool parse_hex_u64(const std::string &s, uint64_t *out)
{
	char *end = nullptr;
	unsigned long long value = strtoull(s.c_str(), &end, 16);
	if (end == s.c_str() || *end != '\0')
		return false;
	*out = static_cast<uint64_t>(value);
	return true;
}

bool parse_mtree_virtio_cfg(const std::string &line, std::string *dev_name,
			    ConfigSpace::ConfigSpaceType *type)
{
	struct prefix_type_t {
		const char *prefix;
		ConfigSpace::ConfigSpaceType type;
	};
	static const prefix_type_t prefixes[] = {
		{ "virtio-pci-common-", ConfigSpace::COMMON },
		{ "virtio-pci-notify-", ConfigSpace::NOTIFY },
		{ "virtio-pci-isr-", ConfigSpace::ISR },
		{ "virtio-pci-device-", ConfigSpace::DEVICE },
	};

	for (const auto &entry : prefixes) {
		size_t pos = line.find(entry.prefix);
		if (pos == std::string::npos)
			continue;
		*dev_name = line.substr(pos + strlen(entry.prefix));
		*type = entry.type;
		return true;
	}

	return false;
}

bool load_manual_ranges_from_mtree(const char *range_file, const std::regex &rx,
				   const char *target_virtio)
{
	bool target_found = false;
	std::ifstream infile(range_file);
	if (!infile) {
		printf("Warning: failed to open manual ranges file %s\n",
		       range_file);
		return false;
	}

	std::string line;
	while (std::getline(infile, line)) {
		if (line.find("ram)") != std::string::npos)
			continue;
		if (line.find("rom)") != std::string::npos)
			continue;

		printf("MATCH: %s\n", line.c_str());
		std::istringstream iss(line);
		uint64_t start, end;
		char c;
		if (!(iss >> std::hex >> start >> c >> std::hex >> end))
			continue;
		if (c != '-')
			continue;

		bool to_fuzz = std::regex_search(line, rx);
		if (to_fuzz) {
			if (start < 0x10000)
				add_pio_region(start, end - start);
			else
				add_mmio_region(start, end - start);
			printf("Will fuzz: %s\n", line.c_str());
		}

		std::string dev_name;
		ConfigSpace::ConfigSpaceType type;
		if (!parse_mtree_virtio_cfg(line, &dev_name, &type))
			continue;

		printf("Found virtio device cfg: %s, %lx - %lx\n",
		       dev_name.c_str(), start, end);
		if (get_vqueue_manager().create_virtio_device(dev_name, to_fuzz))
			get_vqueue_manager().add_config_space(dev_name, type,
						      start, end - start);
		if (target_virtio && to_fuzz && dev_name == target_virtio)
			target_found = true;
	}

	return target_found;
}

struct lspci_cap_t {
	ConfigSpace::ConfigSpaceType type;
	uint64_t address;
	size_t size;
	bool has_multiplier;
	unsigned long multiplier;
};

bool load_manual_ranges_from_lspci(const char *lspci_path,
				   const char *target_virtio)
{
	const char *match_string = lspci_match_string_for_target(target_virtio);
	if (!match_string)
		return false;

	std::ifstream infile(lspci_path);
	if (!infile) {
		printf("Warning: failed to open lspci fallback file %s\n",
		       lspci_path);
		return false;
	}

	static const std::regex region_re(
		"^\\s*Region\\s+([0-9]+):\\s+Memory at\\s+([0-9A-Fa-f]+)");
	static const std::regex cap_re(
		"^\\s*Capabilities: \\[([0-9A-Fa-f]+)\\] Vendor Specific "
		"Information: VirtIO: ([A-Za-z<>]+)");
	static const std::regex detail_re(
		"^\\s*BAR=([0-9]+)\\s+offset=([0-9A-Fa-f]+)\\s+size="
		"([0-9A-Fa-f]+)(?:\\s+multiplier=([0-9A-Fa-f]+))?");

	auto flush_block = [&](const std::vector<std::string> &block) -> bool {
		if (block.empty())
			return false;
		if (block[0].find(match_string) == std::string::npos)
			return false;

		std::map<unsigned, uint64_t> bar_bases;
		std::vector<lspci_cap_t> caps;

		for (size_t i = 1; i < block.size(); i++) {
			std::smatch match;
			if (std::regex_search(block[i], match, region_re)) {
				uint64_t bar = 0, base = 0;
				if (parse_hex_u64(match[1].str(), &bar) &&
				    parse_hex_u64(match[2].str(), &base)) {
					bar_bases[static_cast<unsigned>(bar)] = base;
				}
				continue;
			}

			if (!std::regex_search(block[i], match, cap_re))
				continue;

			ConfigSpace::ConfigSpaceType type;
			const std::string cfg_name = match[2].str();
			if (cfg_name == "CommonCfg")
				type = ConfigSpace::COMMON;
			else if (cfg_name == "Notify")
				type = ConfigSpace::NOTIFY;
			else if (cfg_name == "ISR")
				type = ConfigSpace::ISR;
			else if (cfg_name == "DeviceCfg")
				type = ConfigSpace::DEVICE;
			else
				continue;

			if (i + 1 >= block.size()) {
				printf("Warning: missing lspci detail line after %s "
				       "capability in %s\n",
				       cfg_name.c_str(), lspci_path);
				continue;
			}

			std::smatch detail_match;
			if (!std::regex_search(block[i + 1], detail_match,
					       detail_re)) {
				printf("Warning: malformed lspci detail line after %s "
				       "capability in %s\n",
				       cfg_name.c_str(), lspci_path);
				continue;
			}

			uint64_t bar = 0, offset = 0, size = 0;
			uint64_t multiplier = 0;
			if (!parse_hex_u64(detail_match[1].str(), &bar) ||
			    !parse_hex_u64(detail_match[2].str(), &offset) ||
			    !parse_hex_u64(detail_match[3].str(), &size)) {
				continue;
			}

			auto bar_it = bar_bases.find(static_cast<unsigned>(bar));
			if (bar_it == bar_bases.end()) {
				printf("Warning: BAR %lu not found for %s in %s\n",
				       static_cast<unsigned long>(bar),
				       cfg_name.c_str(), lspci_path);
				continue;
			}

			lspci_cap_t cap = {
				type,
				bar_it->second + offset,
				static_cast<size_t>(size),
				false,
				0,
			};
			if (detail_match.size() > 4 && detail_match[4].matched &&
			    parse_hex_u64(detail_match[4].str(), &multiplier)) {
				cap.has_multiplier = true;
				cap.multiplier =
					static_cast<unsigned long>(multiplier);
			}
			caps.push_back(cap);
		}

		if (caps.empty()) {
			printf("Warning: matched %s in %s but found no usable "
			       "VirtIO capability ranges\n",
			       target_virtio, lspci_path);
			return false;
		}

		printf("Target virtio device %s not found in mtree, using lspci "
		       "fallback from %s\n",
		       target_virtio, lspci_path);
		get_vqueue_manager().create_virtio_device(target_virtio, true);
		for (const auto &cap : caps) {
			add_mmio_region(cap.address, cap.size);
			get_vqueue_manager().add_config_space(target_virtio,
						      cap.type,
						      cap.address,
						      cap.size);
			printf("Found lspci virtio cfg: %s type %d @ %lx + %zx\n",
			       target_virtio, cap.type, cap.address, cap.size);
			if (cap.type == ConfigSpace::NOTIFY &&
			    cap.has_multiplier) {
				auto *dev = get_vqueue_manager()
						    .get_vdev_by_name(target_virtio);
				if (dev)
					dev->multiplier = cap.multiplier;
			}
		}

		return true;
	};

	std::vector<std::string> block;
	std::string line;
	while (std::getline(infile, line)) {
		if (line_is_blank(line)) {
			if (flush_block(block))
				return true;
			block.clear();
			continue;
		}
		block.push_back(line);
	}

	return flush_block(block);
}

} // namespace

void load_manual_ranges(char* range_file, char* range_regex,
			std::map<uint16_t, uint16_t> &pio_regions,
			std::map<bx_address, uint32_t> &mmio_regions)
{
	(void) pio_regions;
	(void) mmio_regions;
	assert(range_file);
	assert(range_regex);

	std::regex rx(range_regex);
	const char *target_virtio =
		target_virtio_from_range_regex(range_regex);
	bool target_found =
		load_manual_ranges_from_mtree(range_file, rx, target_virtio);

	if (!target_found && target_virtio) {
		const char *base = snapshot_base();
		if (!base) {
			printf("Warning: SNAPSHOT_BASE is not set, cannot use "
			       "lspci fallback for %s\n",
			       target_virtio);
		} else {
			std::string lspci_path = std::string(base) + "/lspci";
			if (!load_manual_ranges_from_lspci(lspci_path.c_str(),
							   target_virtio)) {
				printf("Warning: failed to find target virtio device "
				       "%s in mtree or lspci\n",
				       target_virtio);
			}
		}
	}

	get_vqueue_manager().group_vrings_by_page();
}

void load_ram_regions_from_iomem(const char* iomem_path) {
	if (iomem_path) {
		std::ifstream iomem_file(iomem_path);
		std::string line;
		while (std::getline(iomem_file, line))
		{
			if (line.find("RAM") == std::string::npos) {
				continue;
			}
			std::istringstream iss(line);
			uint64_t start, end;
			char c;
			if (!(iss >> std::hex  >> start >> c >>  std::hex >> end)) { continue; }
			if (c != '-') continue;;
			add_ram_region(start, end-start);
			printf("Found RAM region from iomem: %lx - %lx\n", start, end);
		}
	}
}
