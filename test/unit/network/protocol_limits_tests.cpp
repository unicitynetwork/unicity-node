// Security quick tests (ported to test2)

#include <catch_amalgamated.hpp>
#include "network/message.hpp"
#include "network/protocol.hpp"
#include <vector>

using namespace unicity;
using namespace unicity::protocol;

TEST_CASE("Security: VarInt rejects values > MAX_SIZE", "[security][quick][varint]") {
    std::vector<uint8_t> buffer; buffer.push_back(0xFF); uint64_t huge = 33ULL*1024*1024; for(int i=0;i<8;i++) buffer.push_back((huge>>(i*8))&0xFF);
    message::MessageDeserializer d(buffer); (void)d.read_varint(); REQUIRE(d.has_error());
}

TEST_CASE("Security: VarInt accepts MAX_SIZE exactly", "[security][quick][varint]") {
    // MAX_SIZE = 0x02000000 (33,554,432) fits in 32 bits, so must use 5-byte encoding (0xfe prefix)
    // Old test used 9-byte encoding (0xff prefix) which is non-canonical and now correctly rejected
    std::vector<uint8_t> buffer; buffer.push_back(0xfe); uint64_t v=MAX_SIZE; for(int i=0;i<4;i++) buffer.push_back((v>>(i*8))&0xFF);
    message::MessageDeserializer d(buffer); uint64_t res=d.read_varint(); REQUIRE_FALSE(d.has_error()); REQUIRE(res==MAX_SIZE);
}

TEST_CASE("Security: VarInt rejects 18 EB allocation", "[security][quick][varint]") {
    std::vector<uint8_t> buffer; buffer.push_back(0xFF); for(int i=0;i<8;i++) buffer.push_back(0xFF);
    message::MessageDeserializer d(buffer); (void)d.read_varint(); REQUIRE(d.has_error());
}

TEST_CASE("Security: GETHEADERS rejects > MAX_LOCATOR_SZ hashes", "[security][quick][getheaders]") {
    message::MessageSerializer s; s.write_uint32(PROTOCOL_VERSION); s.write_varint(1000);
    for(int i=0;i<10;i++){ std::array<uint8_t,32> h; h.fill(0xAA); s.write_bytes(h.data(), h.size()); }
    std::array<uint8_t,32> stop; stop.fill(0x00); s.write_bytes(stop.data(), stop.size());
    message::GetHeadersMessage msg; bool ok=msg.deserialize(s.data().data(), s.data().size()); REQUIRE_FALSE(ok);
}

TEST_CASE("Security: GETHEADERS accepts MAX_LOCATOR_SZ exactly", "[security][quick][getheaders]") {
    message::MessageSerializer s; s.write_uint32(PROTOCOL_VERSION); s.write_varint(MAX_LOCATOR_SZ);
    for(unsigned i=0;i<MAX_LOCATOR_SZ;i++){ std::array<uint8_t,32> h; h.fill((uint8_t)i); s.write_bytes(h.data(), h.size()); }
    std::array<uint8_t,32> stop; stop.fill(0x00); s.write_bytes(stop.data(), stop.size());
    message::GetHeadersMessage msg; bool ok=msg.deserialize(s.data().data(), s.data().size()); REQUIRE(ok); REQUIRE(msg.block_locator_hashes.size()==MAX_LOCATOR_SZ);
}

TEST_CASE("Security: Message header rejects length > MAX_PROTOCOL_MESSAGE_LENGTH", "[security][quick][message]") {
    std::vector<uint8_t> hdr(MESSAGE_HEADER_SIZE); hdr[0]=hdr[1]=hdr[2]=hdr[3]=0xC0; hdr[4]='t'; hdr[5]='e'; hdr[6]='s'; hdr[7]='t'; for(int i=8;i<16;i++) hdr[i]=0; uint32_t huge=9*1000*1000; hdr[16]=huge&0xFF; hdr[17]=(huge>>8)&0xFF; hdr[18]=(huge>>16)&0xFF; hdr[19]=(huge>>24)&0xFF; for(int i=20;i<24;i++) hdr[i]=0;
    protocol::MessageHeader h; bool ok=message::deserialize_header(hdr.data(), hdr.size(), h); REQUIRE_FALSE(ok);
}

TEST_CASE("Security: Message header accepts MAX_PROTOCOL_MESSAGE_LENGTH exactly", "[security][quick][message]") {
    std::vector<uint8_t> hdr(MESSAGE_HEADER_SIZE); hdr[0]=hdr[1]=hdr[2]=hdr[3]=0xC0; hdr[4]='t'; hdr[5]='e'; hdr[6]='s'; hdr[7]='t'; for(int i=8;i<16;i++) hdr[i]=0; uint32_t len=MAX_PROTOCOL_MESSAGE_LENGTH; hdr[16]=len&0xFF; hdr[17]=(len>>8)&0xFF; hdr[18]=(len>>16)&0xFF; hdr[19]=(len>>24)&0xFF; for(int i=20;i<24;i++) hdr[i]=0;
    protocol::MessageHeader h; bool ok=message::deserialize_header(hdr.data(), hdr.size(), h); REQUIRE(ok); REQUIRE(h.length==MAX_PROTOCOL_MESSAGE_LENGTH);
}
