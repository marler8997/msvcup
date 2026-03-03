// pub const Iterator = std.zip.Iterator(std.fs.File.SeekableStream);

// This is mostly copied from std.zip. std.zip should be refactored
// so we don't have to copy this.
pub fn extract(
    self: std.zip.Iterator.Entry,
    stream: *std.fs.File.Reader,
    writer: *std.Io.Writer,
) !u32 {
    const local_data_header_offset: u64 = local_data_header_offset: {
        const local_header = blk: {
            try stream.seekTo(self.file_offset);
            break :blk try stream.interface.takeStruct(LocalFileHeader, .little);
        };
        if (!std.mem.eql(u8, &local_header.signature, &local_file_header_sig))
            return error.ZipBadFileOffset;
        if (local_header.version_needed_to_extract != self.version_needed_to_extract)
            return error.ZipMismatchVersionNeeded;
        if (local_header.last_modification_time != self.last_modification_time)
            return error.ZipMismatchModTime;
        if (local_header.last_modification_date != self.last_modification_date)
            return error.ZipMismatchModDate;

        if (@as(u16, @bitCast(local_header.flags)) != @as(u16, @bitCast(self.flags)))
            return error.ZipMismatchFlags;
        if (local_header.crc32 != 0 and local_header.crc32 != self.crc32)
            return error.ZipMismatchCrc32;
        var extents: FileExtents = .{
            .uncompressed_size = local_header.uncompressed_size,
            .compressed_size = local_header.compressed_size,
            .local_file_header_offset = 0,
        };
        if (local_header.extra_len > 0) {
            var extra_buf: [std.math.maxInt(u16)]u8 = undefined;
            const extra = extra_buf[0..local_header.extra_len];

            {
                try stream.seekTo(self.file_offset + @sizeOf(LocalFileHeader) + local_header.filename_len);
                try stream.interface.readSliceAll(extra);
            }

            var extra_offset: usize = 0;
            while (extra_offset + 4 <= local_header.extra_len) {
                const header_id = std.mem.readInt(u16, extra[extra_offset..][0..2], .little);
                const data_size = std.mem.readInt(u16, extra[extra_offset..][2..4], .little);
                const end = extra_offset + 4 + data_size;
                if (end > local_header.extra_len)
                    return error.ZipBadExtraFieldSize;
                const data = extra[extra_offset + 4 .. end];
                switch (@as(ExtraHeader, @enumFromInt(header_id))) {
                    .zip64_info => try readZip64FileExtents(LocalFileHeader, local_header, &extents, data),
                    else => {}, // ignore
                }
                extra_offset = end;
            }
        }

        if (extents.compressed_size != 0 and
            extents.compressed_size != self.compressed_size)
            return error.ZipMismatchCompLen;
        if (extents.uncompressed_size != 0 and
            extents.uncompressed_size != self.uncompressed_size)
            return error.ZipMismatchUncompLen;

        if (local_header.filename_len != self.filename_len)
            return error.ZipMismatchFilenameLen;

        break :local_data_header_offset @as(u64, local_header.filename_len) +
            @as(u64, local_header.extra_len);
    };

    const local_data_file_offset: u64 =
        @as(u64, self.file_offset) +
        @as(u64, @sizeOf(LocalFileHeader)) +
        local_data_header_offset;
    try stream.seekTo(local_data_file_offset);

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // TODO: make sure we're supposed to not pass a buffer here
    // var limited_reader = stream.interface.limited(.limited64(self.compressed_size), &.{});
    std.log.info(
        "--- decompress compressed_size={} uncompressed_size={}",
        .{ self.compressed_size, self.uncompressed_size },
    );
    const crc = try decompress(
        self.compression_method,
        self.uncompressed_size,
        // &limited_reader.interface,
        &stream.interface,
        writer,
    );

    const total_read = stream.logicalPos() - local_data_file_offset;
    std.log.info("total read       : {}", .{total_read});
    std.log.info("compressed size  : {}", .{self.compressed_size});
    // this assert is faililng for some reason?
    // std.debug.assert(total_read >= self.compressed_size);
    // std.log.info("read {} extra bytes", .{total_read - self.compressed_size});

    // if (limited_reader.remaining != .nothing)
    //     return error.ZipDecompressTruncated;
    return crc;
}

/// Decompresses the given data from `reader` into `writer`.  Stops early if more
/// than `uncompressed_size` bytes are processed and verifies that exactly that
/// number of bytes are decompressed.  Returns the CRC-32 of the uncompressed data.
/// `writer` can be anything with a `writeAll(self: *Self, chunk: []const u8) anyerror!void` method.
pub fn decompress(
    method: std.zip.CompressionMethod,
    uncompressed_size: u64,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
) !u32 {
    var hash = std.hash.Crc32.init();
    switch (method) {
        .store => {
            @panic("todo");
            // var buf: [4096]u8 = undefined;
            // while (true) {
            //     const len = try reader.read(&buf);
            //     if (len == 0) break;
            //     try writer.writeAll(buf[0..len]);
            //     hash.update(buf[0..len]);
            //     total_uncompressed += @intCast(len);
            // }
        },
        .deflate => {
            var flate_buffer: [flate.max_window_len]u8 = undefined;
            var decompressor: flate.Decompress = .init(reader, .raw, &flate_buffer);
            var uncompressed_remaining: u64 = uncompressed_size;
            while (uncompressed_remaining > 0) {
                const buffer = try decompressor.reader.peekGreedy(1);
                const chunk = buffer[0..@min(buffer.len, uncompressed_remaining)];
                std.log.info("decompress chunk {}", .{chunk.len});
                try writer.writeAll(chunk);
                hash.update(chunk);
                decompressor.reader.toss(chunk.len);
                uncompressed_remaining -= chunk.len;
                // var buf: [4096]u8 = undefined;
                // const max_read: usize = @min(buf.len, std.math.cast(usize, uncompressed_remaining) orelse buf.len);
                // std.log.info("decompress chunk max_read={}", .{max_read});
                // const len = try decompressor.reader.readSliceShort(buf[0..max_read]);
                // if (len == 0) return error.ZipDeflateTruncated;
                // std.log.info("decompress chunk {}", .{len});
                // try writer.writeAll(buf[0..len]);
                // hash.update(buf[0..len]);
                // uncompressed_remaining -= len;
            }
            // if (br.end != br.start)
            //     return error.ZipDeflateTruncated;
        },
        _ => return error.UnsupportedCompressionMethod,
    }
    return hash.final();
}

const FileExtents = struct {
    uncompressed_size: u64,
    compressed_size: u64,
    local_file_header_offset: u64,
};

fn isMaxInt(uint: anytype) bool {
    return uint == std.math.maxInt(@TypeOf(uint));
}

// // this function is copied from std.zip as it is unfortunately private :(
fn readZip64FileExtents(comptime T: type, header: T, extents: *FileExtents, data: []u8) !void {
    var data_offset: usize = 0;
    if (isMaxInt(header.uncompressed_size)) {
        if (data_offset + 8 > data.len)
            return error.ZipBadCd64Size;
        extents.uncompressed_size = std.mem.readInt(u64, data[data_offset..][0..8], .little);
        data_offset += 8;
    }
    if (isMaxInt(header.compressed_size)) {
        if (data_offset + 8 > data.len)
            return error.ZipBadCd64Size;
        extents.compressed_size = std.mem.readInt(u64, data[data_offset..][0..8], .little);
        data_offset += 8;
    }

    switch (T) {
        std.zip.CentralDirectoryFileHeader => {
            if (isMaxInt(header.local_file_header_offset)) {
                if (data_offset + 8 > data.len)
                    return error.ZipBadCd64Size;
                extents.local_file_header_offset = std.mem.readInt(u64, data[data_offset..][0..8], .little);
                data_offset += 8;
            }
            if (isMaxInt(header.disk_number)) {
                if (data_offset + 4 > data.len)
                    return error.ZipInvalid;
                const disk_number = std.mem.readInt(u32, data[data_offset..][0..4], .little);
                if (disk_number != 0)
                    return error.ZipMultiDiskUnsupported;
                data_offset += 4;
            }
            if (data_offset > data.len)
                return error.ZipBadCd64Size;
        },
        else => {},
    }
}

const std = @import("std");
const flate = std.compress.flate;
const ExtraHeader = std.zip.ExtraHeader;
const LocalFileHeader = std.zip.LocalFileHeader;
const local_file_header_sig = std.zip.local_file_header_sig;
