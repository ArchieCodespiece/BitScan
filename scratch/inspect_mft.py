import struct

with open(r'\\.\D:', 'rb', buffering=0) as f:
    boot = f.read(512)
    bytes_per_sec = struct.unpack('<H', boot[11:13])[0]
    sec_per_cluster = boot[13]
    cluster_size = bytes_per_sec * sec_per_cluster
    mft_lcn = struct.unpack('<q', boot[48:56])[0]
    mft_offset = mft_lcn * cluster_size

    # Read first 1000 MFT records
    f.seek(mft_offset)
    mft_data = f.read(1024 * 1000)

print(f"Read {len(mft_data)} bytes from MFT")

deleted_files = []
all_files = []

for i in range(1000):
    rec = mft_data[i*1024 : (i+1)*1024]
    if len(rec) < 1024:
        break
    magic = rec[:4]
    if magic != b'FILE':
        continue
    
    flags = struct.unpack('<H', rec[22:24])[0]
    in_use = bool(flags & 0x01)
    is_dir = bool(flags & 0x02)
    
    # Parse attributes to find $FILE_NAME (0x30)
    attr_offset = struct.unpack('<H', rec[20:22])[0]
    filename = None
    filesize = 0
    
    curr = attr_offset
    while curr + 8 <= len(rec):
        attr_type = struct.unpack('<I', rec[curr:curr+4])[0]
        if attr_type == 0xFFFFFFFF or attr_type == 0:
            break
        attr_len = struct.unpack('<I', rec[curr+4:curr+8])[0]
        if attr_len == 0 or curr + attr_len > len(rec):
            break
            
        non_res = rec[curr+8]
        if attr_type == 0x30: # $FILE_NAME
            # $FILE_NAME is usually resident
            if non_res == 0:
                res_len = struct.unpack('<I', rec[curr+16:curr+20])[0]
                res_off = struct.unpack('<H', rec[curr+20:curr+22])[0]
                fn_content = rec[curr+res_off : curr+res_off+res_len]
                if len(fn_content) > 66:
                    fn_len = fn_content[64]
                    fn_ns = fn_content[65] # namespace
                    fn_bytes = fn_content[66 : 66 + fn_len*2]
                    try:
                        name_str = fn_bytes.decode('utf-16le')
                        # Prefer Win32 / POSIX namespace (not DOS 8.3)
                        if filename is None or fn_ns in (1, 3):
                            filename = name_str
                    except Exception:
                        pass
        elif attr_type == 0x80: # $DATA
            if non_res == 0:
                filesize = struct.unpack('<I', rec[curr+16:curr+20])[0]
            else:
                filesize = struct.unpack('<Q', rec[curr+48:curr+56])[0]
                
        curr += attr_len

    if filename:
        item = {
            "record": i,
            "filename": filename,
            "in_use": in_use,
            "is_dir": is_dir,
            "filesize": filesize
        }
        all_files.append(item)
        if not in_use and not is_dir:
            deleted_files.append(item)

print(f"Total MFT records scanned: 1000")
print(f"Total named items: {len(all_files)}")
print(f"Deleted files found in MFT: {len(deleted_files)}")
for d in deleted_files:
    print(f"  [DELETED] Record {d['record']}: {d['filename']} (Size: {d['filesize']} bytes)")
