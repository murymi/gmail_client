const std = @import("std");
const TlsClinet = std.crypto.tls.Client;
const net = std.net;
const Allocator = std.mem.Allocator;
const b64 = std.base64;

const Config = struct {
    apps_password: []const u8,
    username: []const u8,
};

const Gmail = struct {
    const Self = @This();

    gpa: Allocator,
    cert_bundle: std.crypto.Certificate.Bundle,
    stream: ?net.Stream,
    tls_client: ?TlsClinet,
    b64_encoder: b64.Base64Encoder,

    var recvBuff: [4096]u8 = undefined;
    var ontls: bool = false;

    pub fn init(
        allocator: Allocator,
    ) !*Self {
        const gmptr = try allocator.create(Self);
        errdefer allocator.destroy(gmptr);

        const chars = [_]u8{
        'A', 
        'B', 
        'C',
        'D',
        'E',
        'F',
        'G',
        'H',
        'I',
        'J',
        'K',
        'L',
        'M',
        'N',
        'O',
        'P',
        'Q',
        'R',
        'S',
        'T',
        'U',
        'V',
        'W',
        'X',
        'Y',
        'Z',
        'a',
        'b',
        'c',
        'd',
        'e',
        'f',
        'g',
        'h',
        'i',
        'j',
        'k',
        'l',
        'm',
        'n',
        'o',
        'p',
        'q',
        'r',
        's',
        't',
        'u',
        'v',
        'w',
        'x',
        'y',
        'z',
        '0',
        '1',
        '2',
        '3',
        '4',
        '5',
        '6',
        '7',
        '8',
        '9',
        '+',
        '/',
        };

        var gm: Self = .{ .gpa = allocator, .cert_bundle = std.crypto.Certificate.Bundle{}, .stream = null, .tls_client = null,
        
        .b64_encoder = b64.Base64Encoder.init(chars, '='),
        };
        errdefer gm.cert_bundle.deinit(allocator);
        try gm.cert_bundle.rescan(gm.gpa);


        gmptr.* = gm;

        return gmptr;
    }

    pub fn connect(self: *Self) !void {
        self.stream = try net.tcpConnectToHost(self.gpa, "smtp.gmail.com", 587);
    }

    pub fn read(self: *Self) !void {
        @memset(&recvBuff, 0);
        if (!ontls) {
            if (self.stream) |s| {
                const readBytes = try s.read(&recvBuff);

                if (readBytes <= 0)
                    @panic("Error connecting");

                std.debug.print("{s}", .{recvBuff});
            } else {
                @panic("Failed to read");
            }
        } else {
            if (self.tls_client) |*s| {
                const readBytes = try s.read(self.stream.?, &recvBuff);

                if (readBytes <= 0)
                    @panic("Error connecting");

                std.debug.print("{s}", .{recvBuff});
            } else {
                @panic("Failed to read");
            }
        }
    }

    pub fn deinit(self: *Self) void {
        self.cert_bundle.deinit(self.gpa);

        if (self.stream) |s| {
            s.close();
        }
    }

    pub fn ehlo(self: *Self) !void {
        try write(self, "EHLO smtp.gmail.com\r\n");
    }

    pub fn startTLS(self: *Self) !void {
        const startTlsMessage = "STARTTLS\r\n";

        if (self.stream) |s| {
            if (s.writeAll(startTlsMessage)) {
                try self.read();

                self.tls_client = try TlsClinet.init(self.stream.?, self.cert_bundle, "smtp.gmail.com");
                if (self.tls_client) |*t| {
                    t.allow_truncation_attacks = true;

                    ontls = true;

                    try self.ehlo();

                    try self.read();
                }
            } else |_| {}

            // error handle here

        } else unreachable;
    }

    fn write(self: *Self, message: []const u8) !void {
        if (!ontls) {
            if (self.stream) |s| {
                try s.writeAll(message);
            } else unreachable;
        } else {
            if (self.tls_client) |*t| {
                _ = try t.write(self.stream.?, message);
            } else unreachable;
        }
    }

    pub fn authLogin(self: *Self) !void {
        if (!ontls) unreachable;
        try write(self, "AUTH LOGIN\r\n");

        try self.read();

        var dest: [1024]u8 = undefined;

        const encodedUsername = self.b64_encoder.encode(&dest, "vycnjagi@gmail.com");


        try self.write(encodedUsername);
        try self.write("\r\n");
        try self.read();


        const encodedPassword = self.b64_encoder.encode(&dest, "zmlw avhn mjun mkss");

        try self.write(encodedPassword);
        try self.write("\r\n");
        try self.read();
        
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var y = try Gmail.init(allocator);
    defer y.deinit();

    try y.connect();

    try y.read();

    try y.ehlo();

    try y.read();

    try y.startTLS();
    std.debug.print("=============================\n", .{});
    try y.authLogin();

}
