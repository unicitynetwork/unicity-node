// Standalone fuzz driver for testing fuzz targets when libFuzzer is not available
// This allows building and basic testing of fuzz targets on systems without libFuzzer

#ifdef STANDALONE_FUZZ_TARGET_DRIVER

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

// Forward declare the fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        fprintf(stderr, "\nNote: This is a standalone driver for testing.\n");
        fprintf(stderr, "For actual fuzzing, rebuild with libFuzzer support:\n");
        fprintf(stderr, "  - Install LLVM/Clang with fuzzer libraries\n");
        fprintf(stderr, "  - Or use the OSS-Fuzz Docker environment\n");
        return 1;
    }

    // Read input file
    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", argv[1]);
        return 1;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        fprintf(stderr, "Error: Cannot read file '%s'\n", argv[1]);
        return 1;
    }

    printf("Testing with input file: %s (%zd bytes)\n", argv[1], size);

    // Call the fuzzer
    int result = LLVMFuzzerTestOneInput(buffer.data(), buffer.size());

    printf("Fuzzer completed successfully (returned %d)\n", result);
    return 0;
}

#endif // STANDALONE_FUZZ_TARGET_DRIVER
