const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("fsnode", "main.c");
    exe.setBuildMode(mode);

    // Add include directories (macOS specific)
    exe.addIncludeDir("include");
    exe.addIncludeDir("/opt/homebrew/Cellar/libmagic/5.45/include");
    exe.addIncludeDir("/opt/homebrew/Cellar/jansson/2.14/include");
    exe.addIncludeDir("/opt/homebrew/Cellar/libuv/1.48.0/include");
    exe.addIncludeDir("/opt/homebrew/Cellar/duckdb/1.0.0/include");
    exe.addIncludeDir("/opt/homebrew/Cellar/zlog/1.2.18/include");
    exe.addIncludeDir("/opt/homebrew/opt/openssl/include");

    // Add library directories (macOS specific)
    exe.addLibPath("/opt/homebrew/Cellar/libmagic/5.45/lib");
    exe.addLibPath("/opt/homebrew/Cellar/jansson/2.14/lib");
    exe.addLibPath("/opt/homebrew/Cellar/libuv/1.48.0/lib");
    exe.addLibPath("/opt/homebrew/Cellar/duckdb/1.0.0/lib");
    exe.addLibPath("/opt/homebrew/Cellar/zlog/1.2.18/lib");
    exe.addLibPath("/opt/homebrew/opt/openssl/lib");

    // Linux specific include directories and lib paths
    if (std.os.target.isLinux()) {
        exe.addIncludeDir("/usr/include/libmagic");
        exe.addIncludeDir("/usr/include/jansson");
        exe.addIncludeDir("/usr/include/libuv");
        exe.addIncludeDir("/usr/include/duckdb");
        exe.addIncludeDir("/usr/include/zlog");
        exe.addIncludeDir("/usr/include/openssl");
        exe.addLibPath("/usr/lib/x86_64-linux-gnu");
    }

    // Link against system libraries
    exe.linkSystemLibrary("magic");
    exe.linkSystemLibrary("jansson");
    exe.linkSystemLibrary("uv");
    exe.linkSystemLibrary("duckdb");
    exe.linkSystemLibrary("zlog");
    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");
    exe.linkSystemLibrary("microhttpd"); // Add microhttpd since it's required

    // Add source files
    exe.addCSourceFile("main.c", &[_][]const u8{});
    exe.addCSourceFile("src/map.c", &[_][]const u8{});
    exe.addCSourceFile("src/env.c", &[_][]const u8{});
    exe.addCSourceFile("src/utils.c", &[_][]const u8{});
    exe.addCSourceFile("src/crypto.c", &[_][]const u8{});
    exe.addCSourceFile("src/list.c", &[_][]const u8{});
    exe.addCSourceFile("src/http.c", &[_][]const u8{});
    exe.addCSourceFile("src/conn.c", &[_][]const u8{});
    exe.addCSourceFile("src/aws.c", &[_][]const u8{});
    exe.addCSourceFile("src/server.c", &[_][]const u8{});
    exe.addCSourceFile("src/fsnode.c", &[_][]const u8{});
    exe.addCSourceFile("src/echo.c", &[_][]const u8{});
    exe.addCSourceFile("src/cdn.c", &[_][]const u8{});

    exe.install();
}