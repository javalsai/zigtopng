const std = @import("std");
const pcap = @cImport(@cInclude("pcap.h"));

// std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
const SNAPLEN: c_int = 262144;
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    _ = &stdout;

    const errbuf: []u8 = try allocator.alloc(u8, pcap.PCAP_ERRBUF_SIZE);
    const c_errbuf: [*c]u8 = @ptrCast(errbuf);
    defer allocator.free(errbuf);

    if (pcap.pcap_init(pcap.PCAP_CHAR_ENC_LOCAL, c_errbuf) != 0) {
        std.debug.print("LIBPCAP(init) ERRROR: {s}\n", .{c_errbuf});
        return error.PcapError;
    }

    const iface = null;
    const promisc = 0; // shouldnt be needed to get packet size
    const buffer_timeout_ms = 5000;
    const handle: *pcap.pcap_t = pcap.pcap_open_live(
        iface,
        SNAPLEN,
        promisc,
        buffer_timeout_ms,
        c_errbuf,
    ) orelse {
        std.debug.print("LIBPCAP(open_live) ERROR: {s}\n", .{c_errbuf});
        return error.PcapError;
    };
    _ = &handle;

    const exit_code = pcap.pcap_loop(handle, -1, handler, null);
    if (exit_code != 0) {
        const err_ptr = pcap.pcap_geterr(handle);
        std.debug.print("LIBPCAP(loop) ERROR({d}): {s}\n", .{ exit_code, err_ptr });
        return error.PcapError;
    }

    try bw.flush();
}

pub fn handler(
    user_data: [*c]u8,
    header: [*c]const pcap.struct_pcap_pkthdr,
    packet: [*c]const u8,
) callconv(.C) void {
    _ = &user_data;
    _ = &header;
    _ = &packet;

    const hdr = header.*;
    std.debug.print("Packet captured: caplen={}, len={}\n", .{ hdr.caplen, hdr.len });
}

// test "simple test" {
//     var list = std.ArrayList(i32).init(std.testing.allocator);
//     defer list.deinit();
//     try list.append(42);
//     try std.testing.expectEqual(@as(i32, 42), list.pop());
// }
