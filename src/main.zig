const std = @import("std");
const TlsClinet = std.crypto.tls.Client;
const net = std.net;
const Allocator = std.mem.Allocator;
const b64 = std.base64;
const userArray = std.ArrayList([]const u8);

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
    receipients: userArray,


    var recvBuff: [4096]u8 = undefined;
    var ontls: bool = false;

    pub fn init(allocator: Allocator, config: Config) !*Self {
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

        var gm: Self = .{
            .gpa = allocator,
            .cert_bundle = std.crypto.Certificate.Bundle{},
            .stream = null,
            .tls_client = null,

            .b64_encoder = b64.Base64Encoder.init(chars, '='),
            .receipients = userArray.init(allocator)
        };

        

        errdefer {
            gm.cert_bundle.deinit(allocator);
            gm.receipients.deinit();
        }

        try gm.cert_bundle.rescan(gm.gpa);

        try gm.connect();
        try gm.read();

        try gm.ehlo();

        try gm.read();

        try gm.startTLS();
        std.debug.print("\n\n", .{});
        try gm.authLogin(config.username, config.apps_password);

        gmptr.* = gm;

        return gmptr;
    }

    fn connect(self: *Self) !void {
        self.stream = try net.tcpConnectToHost(self.gpa, "smtp.gmail.com", 587);
    }

    fn read(self: *Self) !void {
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

    fn ehlo(self: *Self) !void {
        try write(self, "EHLO smtp.gmail.com\r\n");
    }

    fn startTLS(self: *Self) !void {
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

    fn authLogin(self: *Self, username: []const u8, password: []const u8) !void {
        if (!ontls) unreachable;
        try write(self, "AUTH LOGIN\r\n");

        try self.read();

        var dest: [1024]u8 = undefined;

        const encodedUsername = self.b64_encoder.encode(&dest, username);

        try self.write(encodedUsername);
        try self.write("\r\n");
        try self.read();

        const encodedPassword = self.b64_encoder.encode(&dest, password);

        try self.write(encodedPassword);
        try self.write("\r\n");
        try self.read();

        const fmt = try std.fmt.bufPrint(&dest, "MAIL FROM: <{s}>\r\n", .{password});

        try self.write(fmt);
    }

    pub fn rcptToOne(self: *Self, username: []const u8) !void {
        var recpMessage: [1024]u8 = undefined;
        const res = try std.fmt.bufPrint(&recpMessage, "RCPT TO: <{s}>\r\n", .{username});
        try self.write(res);

        try self.read();
        try self.receipients.append(username);
    }

    pub fn rcptToMany(self: *Self, username: [][]const u8) !void {
        var recpMessage: [1024]u8 = undefined;

        for (username) |uname| {
            const res = try std.fmt.bufPrint(&recpMessage, "RCPT TO: <{s}>\r\n", .{uname});
            try self.write(res);
            try self.read();
            try self.receipients.append(uname);
        }

    }

    pub fn send(self: *Self, message: []const u8) !void {
        try self.write("DATA\r\n");
        try self.read();

        var messageFmt: [8192]u8 = undefined;

        const joinedUsers = try std.mem.join(self.gpa, ",", self.receipients.items);
        defer self.gpa.free(joinedUsers);

        errdefer self.gpa.free(joinedUsers);

        const res = try std.fmt.bufPrint(&messageFmt, "Date: Tue, 09 oct 2023 16:26:00\r\n" ++
            "From: vycnjagi@gmail.com\r\n" ++
            "Subject: Hello world\r\n" ++
            "To: {s}\r\n" ++
            "MIME-Version: 1.0\r\n" ++
            "Content-type: text/plain\r\n" ++
            "\r\n" ++
            "{s}\r\n" ++
            "vic.\r\n" ++
            ".\r\n", .{ joinedUsers,message});

            std.debug.print("\n{s}\n", .{joinedUsers});
        try self.write(res);

        try self.read();
    }

    pub fn quit(self: *Self) !void {
        try self.write("QUIT\r\n");
        try self.read();
    } 
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var y = try Gmail.init(allocator, .{ .apps_password = "zmlw avhn mjun mkss", .username = "vycnjagi@gmail.com" });
    
    var users = [_][]const u8{"murimimlvictor@gmail.com", "victornjagi@students.uonbi.ac.ke"};
    
    try y.rcptToMany(&users);
    try y.send("hello world");
    try y.quit();
    defer y.deinit();
}
