#!/bin/bash -eu
# OSS-Fuzz build script for Unicity

# Navigate to source directory
cd $SRC/unicity

# Create build directory
mkdir -p build
cd build

# Configure with fuzzing enabled
# OSS-Fuzz sets CXX, CXXFLAGS, LIB_FUZZING_ENGINE automatically
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_FUZZING=ON \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_C_FLAGS="$CFLAGS"

# Build the project
make -j$(nproc)

# Copy fuzz targets to output directory
cp fuzz/fuzz_block_header $OUT/
cp fuzz/fuzz_varint $OUT/
cp fuzz/fuzz_messages $OUT/
cp fuzz/fuzz_message_header $OUT/
cp fuzz/fuzz_chain_reorg $OUT/
cp fuzz/fuzz_asert_difficulty $OUT/
cp fuzz/fuzz_randomx_pow $OUT/
cp fuzz/fuzz_netaddr_parsing $OUT/
cp fuzz/fuzz_header_validation $OUT/
cp fuzz/fuzz_block_locator $OUT/
cp fuzz/fuzz_atomic_write $OUT/
cp fuzz/fuzz_read_file $OUT/
cp fuzz/fuzz_lock_directory $OUT/

# Create seed corpora for better fuzzing

# Seed corpus for block headers (100 bytes each)
mkdir -p $OUT/fuzz_block_header_seed_corpus
# Create a few valid block headers as seeds
echo -n "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" | xxd -r -p > $OUT/fuzz_block_header_seed_corpus/valid_header_1
zip -j $OUT/fuzz_block_header_seed_corpus.zip $OUT/fuzz_block_header_seed_corpus/*

# Seed corpus for messages (various message types)
mkdir -p $OUT/fuzz_messages_seed_corpus
# Empty messages (VERACK, GETADDR)
echo -n "00" > $OUT/fuzz_messages_seed_corpus/empty_msg
# Ping message (type + 8 bytes nonce)
echo -n "0200000000000000000000" | xxd -r -p > $OUT/fuzz_messages_seed_corpus/ping
zip -j $OUT/fuzz_messages_seed_corpus.zip $OUT/fuzz_messages_seed_corpus/*

# Seed corpus for varint (various varint values)
mkdir -p $OUT/fuzz_varint_seed_corpus
echo -n "00" | xxd -r -p > $OUT/fuzz_varint_seed_corpus/zero
echo -n "fc" | xxd -r -p > $OUT/fuzz_varint_seed_corpus/single_byte
echo -n "fdffff" | xxd -r -p > $OUT/fuzz_varint_seed_corpus/two_bytes
echo -n "feffffffff" | xxd -r -p > $OUT/fuzz_varint_seed_corpus/four_bytes
echo -n "ffffffffffffffffff" | xxd -r -p > $OUT/fuzz_varint_seed_corpus/eight_bytes
zip -j $OUT/fuzz_varint_seed_corpus.zip $OUT/fuzz_varint_seed_corpus/*

# Create dictionaries for structured inputs
cat > $OUT/fuzz_messages.dict << EOF
# Message type selectors
"\x00"
"\x01"
"\x02"
"\x03"
"\x04"
"\x05"
"\x06"
"\x07"
"\x08"
"\x09"
"\x0a"

# Common protocol values
"\xfd"
"\xfe"
"\xff"
"\x00\x00\x00\x00"
"\xff\xff\xff\xff"

# Network address markers
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"
EOF

cat > $OUT/fuzz_block_header.dict << EOF
# Version numbers
"\x01\x00\x00\x00"
"\x02\x00\x00\x00"

# Common nBits values
"\xff\xff\x00\x1d"
"\x1d\x00\xff\xff"

# Null hashes
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
EOF

# Generate seed corpus for chain reorganization fuzzer
cd $SRC/unicity
python3 fuzz/generate_chain_seeds.py
if [ -d "fuzz/corpus" ]; then
    mkdir -p $OUT/fuzz_chain_reorg_seed_corpus
    cp fuzz/corpus/* $OUT/fuzz_chain_reorg_seed_corpus/
    zip -j $OUT/fuzz_chain_reorg_seed_corpus.zip $OUT/fuzz_chain_reorg_seed_corpus/*
fi

echo "Fuzz targets built successfully"
