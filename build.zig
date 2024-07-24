const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("fsnode", "main.c");
    exe.setBuildMode(mode);

    // Add include directories
    exe.addIncludeDir("include");
    exe.addIncludeDir("/opt/homebrew/Cellar/libmagic/5.45/include");
    exe.addIncludeDir("/opt/homebrew/Cellar/jansson/2.14/include");
    exe.addIncludeDir("/opt/homebrew/Cellar/libuv/1.48.0/include");
    exe.addIncludeDir("/opt/homebrew/Cellar/duckdb/1.0.0/include");
    exe.addIncludeDir("/opt/homebrew/Cellar/zlog/1.2.18/include");
    exe.addIncludeDir("/opt/homebrew/opt/openssl/include");

    // Add library directories
    exe.addLibPath("/opt/homebrew/Cellar/libmagic/5.45/lib");
    exe.addLibPath("/opt/homebrew/Cellar/jansson/2.14/lib");
    exe.addLibPath("/opt/homebrew/Cellar/libuv/1.48.0/lib");
    exe.addLibPath("/opt/homebrew/Cellar/duckdb/1.0.0/lib");
    exe.addLibPath("/opt/homebrew/Cellar/zlog/1.2.18/lib");
    exe.addLibPath("/opt/homebrew/opt/openssl/lib");

    // Link against libraries
    exe.linkSystemLibrary("magic");
    exe.linkSystemLibrary("jansson");
    exe.linkSystemLibrary("uv");
    exe.linkSystemLibrary("duckdb");
    exe.linkSystemLibrary("zlog");
    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");

    // Add source files
    exe.addCSourceFile("main.c", &[_][]const u8{});

    exe.install();
}
