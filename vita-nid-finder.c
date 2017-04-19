// vita-nid-finder by TheFloW

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef struct {
	uint16_t attr;
	uint16_t ver;
	char name[27];
	uint8_t type;
	uint32_t gp;
	uint32_t expTop;
	uint32_t expBtm;
	uint32_t impTop;
	uint32_t impBtm;
	uint32_t nid;
	uint32_t unk[3];
	uint32_t start;
	uint32_t stop;
	uint32_t exidxTop;
	uint32_t exidxBtm;
	uint32_t extabTop;
	uint32_t extabBtm;
} __attribute__((packed)) SceModuleInfo;

typedef struct {
	uint16_t size;
	uint8_t lib_version[2];
	uint16_t attribute;
	uint16_t num_functions;
	uint32_t num_vars;
	uint32_t num_tls_vars;
	uint32_t module_nid;
	uint32_t lib_name;
	uint32_t nid_table;
	uint32_t entry_table;
} __attribute__((packed)) SceExportsTable;

typedef struct {
	uint16_t size;
	uint16_t lib_version;
	uint16_t attribute;
	uint16_t num_functions;
	uint16_t num_vars;
	uint16_t num_tls_vars;
	uint32_t reserved1;
	uint32_t module_nid;
	uint32_t lib_name;
	uint32_t reserved2;
	uint32_t func_nid_table;
	uint32_t func_entry_table;
	uint32_t var_nid_table;
	uint32_t var_entry_table;
	uint32_t tls_nid_table;
	uint32_t tls_entry_table;
} __attribute__((packed)) SceImportsTable2xx;

typedef struct {
	uint16_t size;
	uint16_t lib_version;
	uint16_t attribute;
	uint16_t num_functions;
	uint16_t num_vars;
	uint16_t unknown1;
	uint32_t module_nid;
	uint32_t lib_name;
	uint32_t func_nid_table;
	uint32_t func_entry_table;
	uint32_t var_nid_table;
	uint32_t var_entry_table;
} __attribute__((packed)) SceImportsTable3xx;

static void convertToImportsTable3xx(SceImportsTable2xx *import_2xx, SceImportsTable3xx *import_3xx)
{
	memset(import_3xx, 0, sizeof(SceImportsTable3xx));

	if (import_2xx->size == sizeof(SceImportsTable2xx)) {
		import_3xx->size = import_2xx->size;
		import_3xx->lib_version = import_2xx->lib_version;
		import_3xx->attribute = import_2xx->attribute;
		import_3xx->num_functions = import_2xx->num_functions;
		import_3xx->num_vars = import_2xx->num_vars;
		import_3xx->module_nid = import_2xx->module_nid;
		import_3xx->lib_name = import_2xx->lib_name;
		import_3xx->func_nid_table = import_2xx->func_nid_table;
		import_3xx->func_entry_table = import_2xx->func_entry_table;
		import_3xx->var_nid_table = import_2xx->var_nid_table;
		import_3xx->var_entry_table = import_2xx->var_entry_table;
	} else if (import_2xx->size == sizeof(SceImportsTable3xx)) {
		memcpy(import_3xx, import_2xx, sizeof(SceImportsTable3xx));
	}
}

// Output in a compact way
int compact = 0;


int ReadFile(char *file, void *buf, int size) {
	FILE *f = fopen(file, "rb");

	if (!f) {
		fprintf(stderr, "Error opening: %s\n", file);
		return -1;
	}

	int rd = fread(buf, 1, size, f);
	fclose(f);

	return rd;
}

int WriteFile(char *file, void *buf, int size) {
	FILE *f = fopen(file, "wb");

	if (!f) {
		fprintf(stderr, "Error opening: %s for write\n", file);
		return -1;
	}

	int wt = fwrite(buf, 1, size, f);
	fclose(f);

	return wt;
}


int main(int argc, char *argv[])
{
	int count = 0;

	static char text_buf[64 * 1024 * 1024];
	
	compact = 0;
	if (argc >= 5 && !strcmp(argv[1], "-c")) {
		compact = 1;
	}

	if (argc < 4 + compact) {
		fprintf(stderr, "Usage:\n\t%s [-c] seg.bin module_name text_addr\n\n", argv[0]);
		return 1;
	}

	int size = ReadFile(argv[1+compact], text_buf, sizeof(text_buf));

	uint32_t sce_module_info_offset = 0;

	// Get sce_module_info offset
	int i;
	for (i = 0; i < size; i++) {
		if (strcmp((char *)text_buf + i, argv[2+compact]) == 0) {
			sce_module_info_offset = i - 0x4;
			break;
		}
	}

	if (sce_module_info_offset == 0)
		return 1;

	uint32_t text_addr = strtoul(argv[3+compact], NULL, 16);

	SceModuleInfo *mod_info = (SceModuleInfo *)(text_buf + sce_module_info_offset);
	
	if (!compact) {
		printf("- MODULE -\n");
		printf("NAME: %s\n", argv[2+compact]);
		printf("NID: 0x%08X\n", mod_info->nid);
		printf("TEXT_ADDR: 0x%08X\n", text_addr);
		printf("\n\n");

		printf("- EXPORTS -\n");
	} else {
		printf("module %s 0x%08X\n", argv[2+compact], mod_info->nid);
	}
	count = 0;

	i = mod_info->expTop;
	while (i < mod_info->expBtm) {
		SceExportsTable *export = (SceExportsTable *)(text_buf + i);

		if (export->lib_name) {
			char *lib_name = (char *)((uintptr_t)text_buf + (export->lib_name - text_addr));
			uint32_t *nid_table = (uint32_t *)((uintptr_t)text_buf + (export->nid_table - text_addr));
			uint32_t *entry_table = (uint32_t *)((uintptr_t)text_buf + (export->entry_table - text_addr));
			int syscall = export->attribute & 0x4000;
			if (!compact) {
				printf("    LIBRARY %d:\n", count);
				printf("    NAME: %s\n", lib_name);
				printf("    SYSCALL: %s\n", syscall ? "Yes" : "No"); 
				printf("    NID: 0x%08X\n", export->module_nid);

				printf("\n");
			} else {
				printf("library %s %s 0x%08X\n", lib_name, syscall? "yes" : "no", export->module_nid);				
			}
			int j;
			for (j = 0; j < export->num_functions; j++) {
				if (!compact)
					printf("      NID %d: 0x%08X\n", j, nid_table[j]);
				else
					printf("function 0x%08X\n", nid_table[j]);
			}

			if (!compact)
				printf("\n");

			count++;
		}

		i += export->size;
	}
	
	if (!compact) { 
		printf("\n\n");

		printf("- IMPORTS -\n");

		i = mod_info->impTop;
		while (i < mod_info->impBtm) {
			SceImportsTable3xx import;
			convertToImportsTable3xx((void *)text_buf + i, &import);

			if (import.lib_name) {
				char *lib_name = (char *)((uintptr_t)text_buf + (import.lib_name - text_addr));
				uint32_t *nid_table = (uint32_t *)((uintptr_t)text_buf + (import.func_nid_table - text_addr));
				uint32_t *entry_table = (uint32_t *)((uintptr_t)text_buf + (import.func_entry_table - text_addr));

				printf("  LIBRARY %d:\n", count);
				printf("    NAME: %s\n", lib_name);
				printf("    NID: 0x%08X\n", import.module_nid);

				printf("\n");

				int j;
				for (j = 0; j < import.num_functions; j++) {
					printf("      NID %d: 0x%08X\n", j, nid_table[j]);
				}

				printf("\n");

				count++;
			}

			i += import.size;
		}
	}
	return 0;
}
