#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>

#include "util.h"

const std::unordered_map<std::string, options> lab_options = {
    {"bpf", BPF_REDIRECT_INFO},
    {"dm", DM_DIRTY_LOG_TYPE}
};

void print_help()
{
    std::cout << "This program can print information about two structures:\n";
    std::cout << "dm_dirty_log_type and bpf_redirect_info\n";
    std::cout << "It is impossible to specify anything about them, so you can type either 'dm' or 'bpf' to get information\n";
}

std::string get_input()
{
    std::cout << ">";
    std::string input;
    std::getline(std::cin, input);
    input.erase(std::remove_if(input.begin(), input.end(),
                               [](unsigned char c)
                               { return std::isspace(c); }),
                input.end());
    return input;
}

int get_option()
{
    std::string input = get_input();

    while (!lab_options.count(input))
    {
        std::cout << "Invalid input, enter your request again\n";
        input = get_input();
    }
    return lab_options.at(input);
}

int main()
{
    std::ofstream proc_write_file{"/proc/lab2out"};
    if (!proc_write_file) {
        std::cout << "Needed proc file doesn't exist\n";
        return 0;
    }

    print_help();

    int option = get_option();
    proc_write_file << std::to_string(option);
    proc_write_file.close();

    std::ifstream proc_read_file{"/proc/lab2out"};
    if (!proc_read_file) {
        std::cout << "Needed proc file doesn't exist\n";
        return 0;
    }

    std::string output;
    while (std::getline(proc_read_file, output))
    {
        std::cout << output << "\n";
    }

    return 0;
}