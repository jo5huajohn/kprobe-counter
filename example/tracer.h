#ifndef TRACER_H_
#define TRACER_H_

enum ksyms {
	BTRFS_LOOKUP = 0,
	BTRFS_GETATTR = 1,
	BTRFS_SETATTR = 2,
	BTRFS_FILE_READ_ITER = 3,
	BTRFS_FILE_WRITE_ITER = 4,
	BTRFS_SYNC_FILE = 5,
	BTRFS_CREATE = 6,
	BTRFS_UNLINK = 7,
	BTRFS_MKDIR = 8,
	BTRFS_RENAME = 9,
	NUM_KSYMS
};

static inline const char *ksyms_enum_to_string(enum ksyms ksym) {
	static const char *strings[] = {
		"btrfs_lookup", 
		"btrfs_getattr", 
		"btrfs_setattr", 
		"btrfs_file_read_iter", 
		"btrfs_file_write_iter", 
		"btrfs_sync_file", 
		"btrfs_create", 
		"btrfs_unlink", 
		"btrfs_mkdir", 
		"btrfs_rename", 
	};
	
	return strings[ksym];
}

#endif
