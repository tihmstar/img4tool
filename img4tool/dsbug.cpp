//  dsbug.cpp
//  img4tool helper

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <thread>

static const std::vector<std::string> g_keywords = {
    "typereq",
    "type req",
    "TypeReq",
    "TypeReq",
    "TypeReq",
    "ERROR",
    "Error",
    "error"
};

static bool containsKeyword(const std::string &line, const std::string &keyword) {
    auto it = std::search(
        line.begin(), line.end(),
        keyword.begin(), keyword.end(),
        [](char a, char b){ return std::tolower(a) == std::tolower(b); }
    );
    return it != line.end();
}

static std::string explainLine(const std::string &line) {
    if (containsKeyword(line, "typereq") || containsKeyword(line, "type req") || containsKeyword(line, "TypeReq")) {
        return "[DSBUG] typereq detected: this usually means a restore type/request mismatch or unsupported restore component. "
               "Check your IPSW/IMG4 loader chain, signing, and the exact component type being restored.";
    }
    if (containsKeyword(line, "error")) {
        return "[DSBUG] generic error line detected. Review surrounding restore log lines for more details and verify restore payloads.";
    }
    return "";
}

static void printMatch(const std::vector<std::string> &context, size_t matchIndex, const std::string &source) {
    std::cout << "\n[DSBUG] Match in " << source << " at line " << (matchIndex + 1) << ":\n";
    size_t start = (matchIndex > 0 ? matchIndex - 1 : 0);
    size_t end = std::min(matchIndex + 1, context.size() - 1);
    if (matchIndex > 0) {
        std::cout << "  " << start + 1 << ": " << context[start] << "\n";
    }
    std::cout << "> " << matchIndex + 1 << ": " << context[matchIndex] << "\n";
    if (matchIndex + 1 < context.size()) {
        std::cout << "  " << end + 1 << ": " << context[end] << "\n";
    }
    std::string explanation = explainLine(context[matchIndex]);
    if (!explanation.empty()) {
        std::cout << explanation << "\n";
    }
}

static int processStream(std::istream &input, const std::string &source, bool verbose) {
    std::vector<std::string> lines;
    std::string line;
    size_t lineNo = 0;
    bool found = false;

    while (std::getline(input, line)) {
        lines.push_back(line);
        size_t idx = lines.size() - 1;
        for (auto &keyword : g_keywords) {
            if (containsKeyword(line, keyword)) {
                printMatch(lines, idx, source);
                found = true;
                if (!verbose) {
                    break;
                }
            }
        }
        lineNo++;
    }

    if (!found) {
        std::cout << "[DSBUG] No matching typereq/error lines were found in " << source << ".\n";
    }
    return found ? 0 : 1;
}

static void followFile(const std::string &path, bool verbose) {
    std::ifstream input;
    std::string line;
    input.open(path);
    if (!input.is_open()) {
        std::cerr << "[DSBUG] Failed to open file: " << path << "\n";
        return;
    }
    while (std::getline(input, line)) {
        ;
    }

    while (true) {
        while (std::getline(input, line)) {
            for (auto &keyword : g_keywords) {
                if (containsKeyword(line, keyword)) {
                    std::cout << "[DSBUG] Live match: " << line << "\n";
                    std::string explanation = explainLine(line);
                    if (!explanation.empty()) {
                        std::cout << explanation << "\n";
                    }
                    if (!verbose) {
                        break;
                    }
                }
            }
        }
        if (input.eof()) {
            input.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        } else {
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    bool watch = false;
    bool verbose = false;
    std::string path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: dsbug [OPTIONS] [FILE]\n"
                      << "  If FILE is omitted, dsbug reads from stdin.\n"
                      << "Options:\n"
                      << "  -h, --help    Show this help text.\n"
                      << "  -w, --watch   Follow FILE like tail -f and report new lines.\n"
                      << "  -v, --verbose Show all matched lines, not just the first match.\n";
            return 0;
        }
        if (arg == "-w" || arg == "--watch") {
            watch = true;
            continue;
        }
        if (arg == "-v" || arg == "--verbose") {
            verbose = true;
            continue;
        }
        if (path.empty()) {
            path = arg;
        }
    }

    if (watch && path.empty()) {
        std::cerr << "[DSBUG] Watch mode requires a file path.\n";
        return 1;
    }

    if (watch) {
        followFile(path, verbose);
        return 0;
    }

    if (path.empty()) {
        return processStream(std::cin, "stdin", verbose);
    }

    std::ifstream input(path);
    if (!input.is_open()) {
        std::cerr << "[DSBUG] Failed to open file: " << path << "\n";
        return 2;
    }
    return processStream(input, path, verbose);
}
