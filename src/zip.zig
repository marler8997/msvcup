pub const Iterator = std.zip.Iterator(std.fs.File.SeekableStream);

// This is mostly copied from std.zip. std.zip should be refactored
// so we don't have to copy this.
pub fn extract(
    entry: Iterator.Entry,
    stream: std.fs.File.SeekableStream,
    file_writer: std.fs.File.Writer,
) !u32 {
    const local_data_header_offset: u64 = local_data_header_offset: {
        const local_header = blk: {
            try stream.seekTo(entry.file_offset);
            break :blk try stream.context.reader().readStructEndian(std.zip.LocalFileHeader, .little);
        };
        if (!std.mem.eql(u8, &local_header.signature, &std.zip.local_file_header_sig))
            return error.ZipBadFileOffset;
        if (local_header.version_needed_to_extract != entry.version_needed_to_extract)
            return error.ZipMismatchVersionNeeded;
        if (local_header.last_modification_time != entry.last_modification_time)
            return error.ZipMismatchModTime;
        if (local_header.last_modification_date != entry.last_modification_date)
            return error.ZipMismatchModDate;

        if (@as(u16, @bitCast(local_header.flags)) != @as(u16, @bitCast(entry.flags)))
            return error.ZipMismatchFlags;
        if (local_header.crc32 != 0 and local_header.crc32 != entry.crc32)
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
                try stream.seekTo(entry.file_offset + @sizeOf(std.zip.LocalFileHeader) + local_header.filename_len);
                const len = try stream.context.reader().readAll(extra);
                if (len != extra.len)
                    return error.ZipTruncated;
            }

            var extra_offset: usize = 0;
            while (extra_offset + 4 <= local_header.extra_len) {
                const header_id = std.mem.readInt(u16, extra[extra_offset..][0..2], .little);
                const data_size = std.mem.readInt(u16, extra[extra_offset..][2..4], .little);
                const end = extra_offset + 4 + data_size;
                if (end > local_header.extra_len)
                    return error.ZipBadExtraFieldSize;
                const data = extra[extra_offset + 4 .. end];
                switch (@as(std.zip.ExtraHeader, @enumFromInt(header_id))) {
                    .zip64_info => try readZip64FileExtents(std.zip.LocalFileHeader, local_header, &extents, data),
                    else => {}, // ignore
                }
                extra_offset = end;
            }
        }

        if (extents.compressed_size != 0 and
            extents.compressed_size != entry.compressed_size)
            return error.ZipMismatchCompLen;
        if (extents.uncompressed_size != 0 and
            extents.uncompressed_size != entry.uncompressed_size)
            return error.ZipMismatchUncompLen;

        if (local_header.filename_len != entry.filename_len)
            return error.ZipMismatchFilenameLen;

        break :local_data_header_offset @as(u64, local_header.filename_len) +
            @as(u64, local_header.extra_len);
    };

    const local_data_file_offset: u64 =
        @as(u64, entry.file_offset) +
        @as(u64, @sizeOf(std.zip.LocalFileHeader)) +
        local_data_header_offset;
    try stream.seekTo(local_data_file_offset);
    var limited_reader = std.io.limitedReader(stream.context.reader(), entry.compressed_size);
    const crc = try std.zip.decompress(
        entry.compression_method,
        entry.uncompressed_size,
        limited_reader.reader(),
        file_writer,
    );
    if (limited_reader.bytes_left != 0)
        return error.ZipDecompressTruncated;
    return crc;
}

const FileExtents = struct {
    uncompressed_size: u64,
    compressed_size: u64,
    local_file_header_offset: u64,
};

fn isMaxInt(uint: anytype) bool {
    return uint == std.math.maxInt(@TypeOf(uint));
}
// this function is copied from std.zip as it is unfortunately private :(
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
