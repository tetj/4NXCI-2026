#include "getopt.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "cnmt.h"
#include "nca.h"
#include "nsp.h"
#include "pfs0.h"
#include "types.h"
#include "utils.h"
#include "settings.h"
#include "pki.h"
#include "xci.h"
#include "extkeys.h"
#include "version.h"
#include "threadpool.h"

#ifdef _WIN32
#include <windows.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#endif

/* 4NXCI by The-4n
   Based on hactool by SciresM
   */

// Forward declarations
static void ensure_titledb(void);
static void sanitize_filename(char *name);
static void build_nsp_filename(char *output, size_t output_size, const char *dir_path,
                                const char *title, const char *title_id, const char *suffix,
                                const char *ext);
static int move_file_robust(const char *old_path, const char *new_path);
static int process_nsp_rename(const char *nsp_path, nxci_ctx_t *tool_ctx);
static int read_cnmt_from_nca_in_nsp(FILE *nsp_file, uint64_t nca_offset, uint64_t nca_size,
                                      nxci_ctx_t *tool_ctx,
                                      uint64_t *out_title_id, uint32_t *out_version,
                                      char *out_type, size_t type_size);

#define TITLEDB_FILENAME  "US.en.json"
#define TITLEDB_URL       "https://raw.githubusercontent.com/blawar/titledb/master/US.en.json"
#define TITLEDB_MAX_AGE_SEC (7 * 24 * 60 * 60)  /* 7 days */

// Download US.en.json if missing or older than 7 days
static void ensure_titledb(void)
{
    struct stat st;
    int needs_download = 0;

    if (stat(TITLEDB_FILENAME, &st) != 0)
    {
        printf("Title database not found. Downloading (~77MB)...\n");
        needs_download = 1;
    }
    else
    {
        double age_sec = difftime(time(NULL), st.st_mtime);
        if (age_sec > TITLEDB_MAX_AGE_SEC)
        {
            printf("Title database is %.0f day(s) old. Updating (~77MB)...\n",
                   age_sec / (60.0 * 60.0 * 24.0));
            needs_download = 1;
        }
    }

    if (!needs_download)
        return;

#ifdef _WIN32
    const char *tmp_path = TITLEDB_FILENAME ".tmp";
    printf("Downloading from:\n  %s\n", TITLEDB_URL);

    HRESULT hr = URLDownloadToFileA(NULL, TITLEDB_URL, tmp_path, 0, NULL);
    if (SUCCEEDED(hr))
    {
        remove(TITLEDB_FILENAME);
        if (rename(tmp_path, TITLEDB_FILENAME) == 0)
            printf("Title database updated successfully.\n");
        else
        {
            fprintf(stderr, "Warning: Download succeeded but rename failed (%s)\n", strerror(errno));
            remove(tmp_path);
        }
    }
    else
    {
        fprintf(stderr, "Warning: Failed to download title database (HRESULT: 0x%08lX)\n", hr);
        fprintf(stderr, "         Place %s next to the executable and retry.\n", TITLEDB_FILENAME);
        remove(tmp_path);
    }
#else
    fprintf(stderr, "Warning: Auto-download is Windows-only.\n");
    fprintf(stderr, "         Download %s manually from:\n  %s\n",
            TITLEDB_FILENAME, TITLEDB_URL);
#endif
}

// Function to lookup title name from titledb JSON file
static int lookup_title_name(const char *title_id, char *title_name, size_t title_name_size)
{
    FILE *titledb = fopen("US.en.json", "r");
    if (!titledb)
    {
        // Try alternative names
        titledb = fopen("US.en.json", "r");
        if (!titledb)
        {
            return 0; // File not found
        }
    }

    // Search for the title ID in the JSON file
    // The structure is: "nsuId": { ..., "id": "titleID", ..., "name": "Title Name", ... }
    char line[4096];
    int found = 0;
    int in_correct_entry = 0;

    while (fgets(line, sizeof(line), titledb))
    {
        // Look for "id" field matching our title ID
        if (!in_correct_entry && strstr(line, "\"id\":"))
        {
            char search_pattern[64];
            snprintf(search_pattern, sizeof(search_pattern), "\"%s\"", title_id);

            if (strstr(line, search_pattern))
            {
                in_correct_entry = 1;
                continue;
            }
        }

        // If we found the right entry, look for the "name" field
        if (in_correct_entry && strstr(line, "\"name\":"))
        {
            // Extract the name value
            char *name_start = strchr(line, ':');
            if (name_start)
            {
                name_start = strchr(name_start, '"');
                if (name_start)
                {
                    name_start++; // Skip opening quote
                    char *name_end = strchr(name_start, '"');
                    if (name_end)
                    {
                        size_t name_len = name_end - name_start;
                        if (name_len < title_name_size)
                        {
                            strncpy(title_name, name_start, name_len);
                            title_name[name_len] = '\0';
                            found = 1;
                            break;
                        }
                    }
                }
            }
        }

        // Check if we've reached the end of an entry
        if (in_correct_entry && strstr(line, "},"))
        {
            // End of this entry, reset flag
            in_correct_entry = 0;
        }
    }

    fclose(titledb);
    return found;
}

nsp_ctx_t *application_nsps;
cnmts_ctx_t applications_cnmt_ctx;
nsp_ctx_t *patch_nsps;
cnmts_ctx_t patches_cnmt_ctx;
nsp_ctx_t *addon_nsps;
cnmts_ctx_t addons_cnmt_ctx;

// Task structure for parallel processing
typedef struct {
    nxci_ctx_t *tool_ctx;
    cnmt_xml_ctx_t *cnmt_xml;
    cnmt_ctx_t *cnmt;
    nsp_ctx_t *nsp;
    int index;
    int type; // 0=application, 1=patch, 2=addon
} process_task_t;

// Helper to extract and decrypt the binary CNMT from a .cnmt.nca embedded in an NSP.
// Writes the extracted NCA to a temp file, decrypts it using the keyset in tool_ctx,
// reads the CNMT binary header, and fills the output parameters.
// Returns 1 on success, 0 on failure.
static int read_cnmt_from_nca_in_nsp(FILE *nsp_file, uint64_t nca_offset, uint64_t nca_size,
                                      nxci_ctx_t *tool_ctx,
                                      uint64_t *out_title_id, uint32_t *out_version,
                                      char *out_type, size_t type_size)
{
    const char *tmp_path = "4nxci_cnmt_tmp.nca";

    // Extract the .cnmt.nca bytes to a temporary file
    FILE *tmp = fopen(tmp_path, "wb");
    if (!tmp)
    {
        fprintf(stderr, "Warning: Failed to create temp file for NCA extraction\n");
        return 0;
    }

    fseeko64(nsp_file, (int64_t)nca_offset, SEEK_SET);

    char buf[65536];
    uint64_t remaining = nca_size;
    while (remaining > 0)
    {
        size_t chunk = (remaining > sizeof(buf)) ? sizeof(buf) : (size_t)remaining;
        size_t rd = fread(buf, 1, chunk, nsp_file);
        if (rd == 0)
        {
            break;
        }
        fwrite(buf, 1, rd, tmp);
        remaining -= rd;
    }
    fclose(tmp);

    if (remaining != 0)
    {
        fprintf(stderr, "Warning: Failed to extract NCA from NSP (incomplete read)\n");
        remove(tmp_path);
        return 0;
    }

    // Open the extracted NCA file and decrypt the CNMT
    FILE *nca_file = fopen(tmp_path, "rb");
    if (!nca_file)
    {
        remove(tmp_path);
        return 0;
    }

    nca_ctx_t nca_ctx;
    nca_init(&nca_ctx);
    nca_ctx.file = nca_file;
    nca_ctx.tool_ctx = tool_ctx;

    if (!nca_decrypt_header(&nca_ctx))
    {
        fprintf(stderr, "Warning: Failed to decrypt NCA header (are keys correct?)\n");
        fclose(nca_file);
        remove(tmp_path);
        return 0;
    }

    // Determine crypto generation
    nca_ctx.crypto_type = nca_ctx.header.crypto_type;
    if (nca_ctx.header.crypto_type2 > nca_ctx.header.crypto_type)
    {
        nca_ctx.crypto_type = nca_ctx.header.crypto_type2;
    }
    if (nca_ctx.crypto_type)
    {
        nca_ctx.crypto_type--;
    }

    nca_decrypt_key_area(&nca_ctx);

    // Set up AES-CTR context for section 0 (the PFS0 holding the CNMT binary)
    nca_ctx.section_contexts[0].aes = new_aes_ctx(nca_ctx.decrypted_keys[2], 16, AES_MODE_CTR);
    nca_ctx.section_contexts[0].offset = media_to_real(nca_ctx.header.section_entries[0].media_start_offset);
    nca_ctx.section_contexts[0].sector_ofs = 0;
    nca_ctx.section_contexts[0].file = nca_file;
    nca_ctx.section_contexts[0].crypt_type = CRYPT_CTR;
    nca_ctx.section_contexts[0].header = &nca_ctx.header.fs_headers[0];

    uint64_t ctr_ofs = nca_ctx.section_contexts[0].offset >> 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        nca_ctx.section_contexts[0].ctr[j] = nca_ctx.section_contexts[0].header->section_ctr[0x8 - j - 1];
        nca_ctx.section_contexts[0].ctr[0x10 - j - 1] = (unsigned char)(ctr_ofs & 0xFF);
        ctr_ofs >>= 8;
    }

    // Read the PFS0 header that wraps the CNMT binary inside section 0
    pfs0_header_t pfs0_header;
    uint64_t pfs0_offset = nca_ctx.header.fs_headers[0].pfs0_superblock.pfs0_offset;
    nca_section_fseek(&nca_ctx.section_contexts[0], pfs0_offset);
    nca_section_fread(&nca_ctx.section_contexts[0], &pfs0_header, sizeof(pfs0_header_t));

    int success = 0;

    if (pfs0_header.magic == MAGIC_PFS0 && pfs0_header.num_files > 0)
    {
        // CNMT binary immediately follows the PFS0 header, file-entry table, and string table
        uint64_t cnmt_data_offset = pfs0_offset
            + sizeof(pfs0_header_t)
            + ((uint64_t)pfs0_header.num_files * sizeof(pfs0_file_entry_t))
            + pfs0_header.string_table_size;

        cnmt_header_t cnmt_header;
        nca_section_fseek(&nca_ctx.section_contexts[0], cnmt_data_offset);
        nca_section_fread(&nca_ctx.section_contexts[0], &cnmt_header, sizeof(cnmt_header_t));

        *out_title_id = cnmt_header.title_id;
        *out_version  = cnmt_header.title_version;

        switch (cnmt_header.type)
        {
        case 0x80:
            strncpy(out_type, "Application", type_size - 1);
            break;
        case 0x81:
            strncpy(out_type, "Patch", type_size - 1);
            break;
        case 0x82:
            strncpy(out_type, "AddOnContent", type_size - 1);
            break;
        default:
            snprintf(out_type, type_size, "Unknown(0x%02X)", cnmt_header.type);
            break;
        }
        out_type[type_size - 1] = '\0';

        success = (*out_title_id != 0);
    }
    else
    {
        fprintf(stderr, "Warning: PFS0 magic not found inside .cnmt.nca section\n");
    }

    free_aes_ctx(nca_ctx.section_contexts[0].aes);
    fclose(nca_file);
    remove(tmp_path);
    return success;
}

// Function to read and rename an NSP file based on its metadata
static int process_nsp_rename(const char *nsp_path, nxci_ctx_t *tool_ctx)
{
    printf("===> Processing NSP/NSZ file for renaming: %s\n", nsp_path);

    FILE *nsp_file = fopen(nsp_path, "rb");
    if (!nsp_file)
    {
        fprintf(stderr, "Error: Unable to open NSP file: %s\n", nsp_path);
        return EXIT_FAILURE;
    }

    // Read PFS0 header
    pfs0_header_t header;
    if (fread(&header, sizeof(pfs0_header_t), 1, nsp_file) != 1)
    {
        fprintf(stderr, "Error: Failed to read NSP header\n");
        fclose(nsp_file);
        return EXIT_FAILURE;
    }

    if (header.magic != MAGIC_PFS0)
    {
        fprintf(stderr, "Error: Invalid NSP file (bad magic)\n");
        fclose(nsp_file);
        return EXIT_FAILURE;
    }

    printf("NSP contains %u files\n", header.num_files);

    // Read file entry table
    pfs0_file_entry_t *entries = (pfs0_file_entry_t *)malloc(sizeof(pfs0_file_entry_t) * header.num_files);
    if (fread(entries, sizeof(pfs0_file_entry_t), header.num_files, nsp_file) != header.num_files)
    {
        fprintf(stderr, "Error: Failed to read file entry table\n");
        free(entries);
        fclose(nsp_file);
        return EXIT_FAILURE;
    }

    // Read string table
    char *string_table = (char *)malloc(header.string_table_size);
    if (fread(string_table, 1, header.string_table_size, nsp_file) != header.string_table_size)
    {
        fprintf(stderr, "Error: Failed to read string table\n");
        free(entries);
        free(string_table);
        fclose(nsp_file);
        return EXIT_FAILURE;
    }

    // Find CNMT XML, CNMT NCA, and ticket inside the NSP
    // Data payload begins immediately after header + entry table + string table
    uint64_t data_base = sizeof(pfs0_header_t) +
                         (sizeof(pfs0_file_entry_t) * header.num_files) +
                         header.string_table_size;

    char *cnmt_filename = NULL;
    uint64_t cnmt_xml_offset = 0;
    uint64_t cnmt_xml_size   = 0;
    uint64_t cnmt_nca_offset = 0;
    uint64_t cnmt_nca_size   = 0;
    uint64_t ticket_offset   = 0;
    int has_cnmt_xml = 0;
    int has_cnmt_nca = 0;
    int has_ticket   = 0;

    for (uint32_t i = 0; i < header.num_files; i++)
    {
        char *filename = string_table + entries[i].string_table_offset;

        // .cnmt.xml is a plaintext XML — primary source of title metadata
        if (strstr(filename, ".cnmt.xml") != NULL)
        {
            has_cnmt_xml    = 1;
            cnmt_xml_offset = data_base + entries[i].offset;
            cnmt_xml_size   = entries[i].size;
            printf("Found CNMT XML: %s\n", filename);
        }

        // .cnmt.nca — encrypted metadata NCA (kept for completeness)
        if (strstr(filename, ".cnmt.nca") != NULL)
        {
            cnmt_filename    = filename;
            has_cnmt_nca     = 1;
            cnmt_nca_offset  = data_base + entries[i].offset;
            cnmt_nca_size    = entries[i].size;
            printf("Found CNMT NCA: %s\n", filename);
        }

        // .tik — ticket file present only in titlekey-encrypted NSPs
        if (strstr(filename, ".tik") != NULL)
        {
            has_ticket    = 1;
            ticket_offset = data_base + entries[i].offset;
            printf("Found ticket: %s\n", filename);
        }
    }

    if (!cnmt_filename && !has_cnmt_xml && !has_cnmt_nca)
    {
        fprintf(stderr, "Error: No CNMT file found in NSP\n");
        free(entries);
        free(string_table);
        fclose(nsp_file);
        return EXIT_FAILURE;
    }

    // ----------------------------------------------------------------
    // Extract title ID, content type, and version
    // PRIMARY:  read from .cnmt.xml (plaintext — always present in
    //           NSPs produced by 4NXCI and many other tools)
    // FALLBACK: read title ID from the ticket file (.tik) present in
    //           titlekey-encrypted NSPs
    // ----------------------------------------------------------------
    uint64_t title_id    = 0;
    uint32_t cnmt_version = 0;
    char     cnmt_type[32] = {0};   // "Application", "Patch", "AddOnContent", …
    char     title_id_str[17] = {0};

    if (has_cnmt_xml && cnmt_xml_size > 0 && cnmt_xml_size < (1024u * 1024u))
    {
        char *xml_buf = (char *)malloc(cnmt_xml_size + 1);
        if (xml_buf)
        {
            fseeko64(nsp_file, (int64_t)cnmt_xml_offset, SEEK_SET);
            if (fread(xml_buf, 1, cnmt_xml_size, nsp_file) == cnmt_xml_size)
            {
                xml_buf[cnmt_xml_size] = '\0';

                // <Id>0x010019a01e2f2000</Id>
                char *id_tag = strstr(xml_buf, "<Id>");
                if (id_tag)
                {
                    id_tag += 4;
                    if (id_tag[0] == '0' && (id_tag[1] == 'x' || id_tag[1] == 'X'))
                        id_tag += 2;
                    char tid_hex[17] = {0};
                    strncpy(tid_hex, id_tag, 16);
                    for (int ci = 0; ci < 16; ci++)
                        tid_hex[ci] = (char)toupper((unsigned char)tid_hex[ci]);
                    title_id = strtoull(tid_hex, NULL, 16);
                    snprintf(title_id_str, sizeof(title_id_str), "%016llX",
                             (unsigned long long)title_id);
                    printf("Extracted Title ID from CNMT XML: %s\n", title_id_str);
                }

                // <Type>Application</Type>
                char *type_tag = strstr(xml_buf, "<Type>");
                if (type_tag)
                {
                    type_tag += 6;
                    char *type_end = strchr(type_tag, '<');
                    if (type_end)
                    {
                        size_t type_len = (size_t)(type_end - type_tag);
                        if (type_len < sizeof(cnmt_type))
                        {
                            strncpy(cnmt_type, type_tag, type_len);
                            cnmt_type[type_len] = '\0';
                        }
                    }
                }

                // <Version>65536</Version>
                char *ver_tag = strstr(xml_buf, "<Version>");
                if (ver_tag)
                {
                    ver_tag += 9;
                    cnmt_version = (uint32_t)strtoul(ver_tag, NULL, 10);
                }
            }
            free(xml_buf);
        }
    }

    // Fallback: ticket file (titlekey-encrypted NSPs)
    if (title_id == 0 && has_ticket)
    {
        // Rights ID is at offset 0x2A0 in the ticket; the first 8 bytes are
        // the title ID stored in big-endian order.
        fseeko64(nsp_file, (int64_t)(ticket_offset + 0x2A0), SEEK_SET);
        uint64_t raw = 0;
        if (fread(&raw, sizeof(uint64_t), 1, nsp_file) == 1)
        {
            title_id = ((raw & 0x00000000000000FFULL) << 56) |
                       ((raw & 0x000000000000FF00ULL) << 40) |
                       ((raw & 0x0000000000FF0000ULL) << 24) |
                       ((raw & 0x00000000FF000000ULL) <<  8) |
                       ((raw & 0x000000FF00000000ULL) >>  8) |
                       ((raw & 0x0000FF0000000000ULL) >> 24) |
                       ((raw & 0x00FF000000000000ULL) >> 40) |
                       ((raw & 0xFF00000000000000ULL) >> 56);
            snprintf(title_id_str, sizeof(title_id_str), "%016llX",
                     (unsigned long long)title_id);
            printf("Extracted Title ID from ticket: %s\n", title_id_str);
        }
        else
        {
            fprintf(stderr, "Warning: Failed to read title ID from ticket\n");
        }
    }

    if (title_id == 0)
    {
        // Third fallback: decrypt binary CNMT from the .cnmt.nca using the keyset
        if (has_cnmt_nca && tool_ctx != NULL)
        {
            printf("Attempting to read Title ID from binary CNMT (NCA decryption)...\n");
            if (read_cnmt_from_nca_in_nsp(nsp_file, cnmt_nca_offset, cnmt_nca_size,
                                          tool_ctx, &title_id, &cnmt_version,
                                          cnmt_type, sizeof(cnmt_type)))
            {
                snprintf(title_id_str, sizeof(title_id_str), "%016llX",
                         (unsigned long long)title_id);
                printf("Extracted Title ID from binary CNMT: %s\n", title_id_str);
                printf("Type from binary CNMT: %s\n", cnmt_type);
            }
        }
    }

    if (title_id == 0)
    {
        fprintf(stderr, "Error: Could not extract title ID from NSP metadata\n");
        fprintf(stderr, "       (no .cnmt.xml, no ticket, and NCA decryption failed or unavailable)\n");
        free(entries);
        free(string_table);
        fclose(nsp_file);
        return EXIT_FAILURE;
    }

    // ----------------------------------------------------------------
    // Determine suffix and base title ID for the database lookup
    // ----------------------------------------------------------------
    char suffix[48] = {0};
    uint64_t base_tid = title_id & 0xFFFFFFFFFFFFE000ULL;

    if (cnmt_type[0] != '\0')
    {
        // Use the explicit type from the CNMT XML (most reliable)
        if (strcmp(cnmt_type, "Patch") == 0)
        {
            snprintf(suffix, sizeof(suffix), "[v%u][UPD]", cnmt_version);
            printf("Type: Update/Patch (version %u)\n", cnmt_version);
        }
        else if (strcmp(cnmt_type, "AddOnContent") == 0)
        {
            snprintf(suffix, sizeof(suffix), "[DLC]");
            printf("Type: DLC/Add-on\n");
        }
        else
        {
            // Application, SystemUpdate, DataPatch, etc.
            snprintf(suffix, sizeof(suffix), "[BASE]");
            printf("Type: Base Game (%s)\n", cnmt_type);
        }
    }
    else
    {
        // Fall back to title ID bit pattern (for ticket-only NSPs without XML)
        uint64_t tid_low = title_id & 0x0000000000001FFFULL;
        if (tid_low == 0x800)
        {
            snprintf(suffix, sizeof(suffix), "[v%u][UPD]", cnmt_version);
            printf("Type: Update/Patch\n");
        }
        else if (tid_low >= 0x1000)
        {
            snprintf(suffix, sizeof(suffix), "[DLC]");
            printf("Type: DLC/Add-on\n");
        }
        else
        {
            snprintf(suffix, sizeof(suffix), "[BASE]");
            printf("Type: Base Game\n");
        }
    }

    // Download/refresh US.en.json if needed, then look up title name
    ensure_titledb();

    // Look up title name from titledb
    char title_name[0x200];
    char base_tid_str[17];
    snprintf(base_tid_str, sizeof(base_tid_str), "%016llX", (unsigned long long)base_tid);

    if (lookup_title_name(base_tid_str, title_name, sizeof(title_name)))
    {
        printf("Title Name: %s\n", title_name);
    }
    else
    {
        printf("Title name not found in database, using Title ID\n");
        snprintf(title_name, sizeof(title_name), "%016llX", (unsigned long long)base_tid);
    }

    // Strip characters illegal in Windows filenames (e.g. ':' in "Game: Subtitle")
    sanitize_filename(title_name);

    // Build new filename
    char new_path[MAX_PATH];
    char dir_path[MAX_PATH] = "";

    // Extract directory from original path
    char *last_sep = strrchr(nsp_path, PATH_SEPERATOR);
    if (last_sep != NULL)
    {
        size_t dir_len = last_sep - nsp_path + 1;
        strncpy(dir_path, nsp_path, dir_len);
        dir_path[dir_len] = '\0';
    }

    // Preserve input extension (.nsp or .nsz) in the output filename
    const char *input_ext = ".nsp";
    const char *ext_dot = strrchr(nsp_path, '.');
    if (ext_dot != NULL && (strcmp(ext_dot, ".nsz") == 0 || strcmp(ext_dot, ".NSZ") == 0))
    {
        input_ext = ".nsz";
    }

    build_nsp_filename(new_path, MAX_PATH, dir_path, title_name, title_id_str, suffix, input_ext);

    printf("\nRenaming:\n");
    printf("  From: %s\n", nsp_path);
    printf("    To: %s\n", new_path);

    // Close file before renaming
    free(entries);
    free(string_table);
    fclose(nsp_file);

    // Rename the file.
    // nsp_path comes from argv which is ANSI-encoded (CP_ACP): a filename like
    // "TetrisÂ® Effect Connected" has bytes C2 AE representing U+00C2 U+00AE on
    // disk.  new_path is built from UTF-8 JSON data, so C2 AE means U+00AE (®).
    // Using CP_ACP for the source and CP_UTF8 for the destination lets MoveFileExW
    // find the existing (possibly corrupted) file and write the correct new name.
#ifdef _WIN32
    {
        wchar_t old_path_w[MAX_PATH];
        wchar_t new_path_w[MAX_PATH];
        MultiByteToWideChar(CP_ACP,  0, nsp_path, -1, old_path_w, MAX_PATH);
        MultiByteToWideChar(CP_UTF8, 0, new_path, -1, new_path_w, MAX_PATH);

        if (MoveFileExW(old_path_w, new_path_w, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
        {
            printf("Successfully renamed NSP/NSZ file!\n");
            return EXIT_SUCCESS;
        }
        fprintf(stderr, "Error: Failed to rename NSP file (error: %lu)\n", GetLastError());
        return EXIT_FAILURE;
    }
#else
    if (move_file_robust(nsp_path, new_path) == 0)
    {
        printf("Successfully renamed NSP/NSZ file!\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "Error: Failed to rename NSP file (errno: %d - %s)\n",
            errno, strerror(errno));
    return EXIT_FAILURE;
#endif
}

// Worker function for processing applications/addons
static void process_gamecard_worker(void *arg) {
    process_task_t *task = (process_task_t *)arg;
    int task_index = task->index;  // Save index BEFORE freeing
    printf("DEBUG: Worker thread - Starting gamecard task for index %d\n", task_index);
    cnmt_gamecard_process(task->tool_ctx, task->cnmt_xml, task->cnmt, task->nsp);
    printf("DEBUG: Worker thread - cnmt_gamecard_process() returned for index %d\n", task_index);
    printf("DEBUG: Worker thread - Freeing task structure for index %d\n", task_index);
    free(task);
    printf("DEBUG: Worker thread - Task %d completed, returning to pool\n", task_index);
}

// Worker function for processing patches
static void process_download_worker(void *arg) {
    process_task_t *task = (process_task_t *)arg;
    int task_index = task->index;  // Save index BEFORE freeing
    printf("DEBUG: Worker thread - Starting download task for index %d\n", task_index);
    cnmt_download_process(task->tool_ctx, task->cnmt_xml, task->cnmt, task->nsp);
    printf("DEBUG: Worker thread - cnmt_download_process() returned for index %d\n", task_index);
    printf("DEBUG: Worker thread - Freeing task structure for index %d\n", task_index);
    free(task);
    printf("DEBUG: Worker thread - Task %d completed, returning to pool\n", task_index);
}

#ifdef _WIN32
// Get available physical memory in bytes
static uint64_t get_available_memory(void)
{
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    return (uint64_t)memInfo.ullAvailPhys;
}

// Get file size
static uint64_t get_file_size(FILE *file)
{
    fseeko64(file, 0, SEEK_END);
    uint64_t size = ftello64(file);
    fseeko64(file, 0, SEEK_SET);
    return size;
}

// Helper function to move/rename files using Windows API for better reliability
static int move_file_robust(const char *old_path, const char *new_path)
{
    // Always use the wide-char API so that UTF-8 encoded titles (e.g. ® ™ é)
    // are preserved correctly in the filename.  The ANSI rename() interprets
    // UTF-8 multi-byte sequences through the current ANSI code page (usually
    // Windows-1252), which corrupts characters like ® (0xC2 0xAE → "Â®").
    wchar_t old_path_w[MAX_PATH];
    wchar_t new_path_w[MAX_PATH];

    MultiByteToWideChar(CP_UTF8, 0, old_path, -1, old_path_w, MAX_PATH);
    MultiByteToWideChar(CP_UTF8, 0, new_path, -1, new_path_w, MAX_PATH);

    if (MoveFileExW(old_path_w, new_path_w, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
        return 0;

    return -1;
}
#else
static int move_file_robust(const char *old_path, const char *new_path)
{
    return rename(old_path, new_path);
}
#endif

// Helper function to strip Windows-illegal filename characters from a title string
// Removes: / : ? * " < > |
static void sanitize_filename(char *name)
{
    char *dst = name;
    for (const char *src = name; *src; src++)
    {
        unsigned char c = (unsigned char)*src;
        if (c == '/' || c == ':' || c == '?' || c == '*' || c == '"' ||
            c == '<' || c == '>' || c == '|')
            continue; /* drop illegal character */
        *dst++ = *src;
    }
    *dst = '\0';
}

// Helper function to build new filename with title prefix and suffix
static void build_nsp_filename(char *output, size_t output_size, const char *dir_path,
                                const char *title, const char *title_id, const char *suffix,
                                const char *ext)
{
    snprintf(output, output_size, "%s%s[%s]%s%s",
             dir_path ? dir_path : "", title, title_id, suffix, ext);
}

// Helper function to decode Nintendo Switch version number
// Format: uint32 where bits [31:26]=major, [25:16]=minor, [15:0]=micro
static void decode_version(uint32_t version, char *output, size_t output_size)
{
    uint32_t major = (version >> 26) & 0x3F;
    uint32_t minor = (version >> 16) & 0x3FF;
    uint32_t micro = version & 0xFFFF;

    if (micro > 0)
        snprintf(output, output_size, "%u.%u.%u", major, minor, micro);
    else if (minor > 0)
        snprintf(output, output_size, "%u.%u", major, minor);
    else
        snprintf(output, output_size, "%u", major);
}

// Print Usage
static void usage(void)
{
    fprintf(stderr,
            "Usage: %s [options...] <path_to_file.xci>\n"
            "       %s -r <path_to_file.nsp|.nsz>\n\n"
            "Options:\n"
            "-k, --keyset             Set keyset filepath, default filepath is ." OS_PATH_SEPARATOR "keys.dat\n"
            "-h, --help               Display usage\n"
            "-t, --tempdir            Set temporary directory path\n"
            "-o, --outdir             Set output directory path\n"
            "-c, --convert            Use Titlename instead of Titleid in nsp name\n"
            "-d, --delete             Delete source XCI file after successful conversion\n"
            "-r, --rename             Rename NSP/NSZ file to match naming format\n"
            "--keepncaid              Keep current ncas ids\n",
            USAGE_PROGRAM_NAME, USAGE_PROGRAM_NAME);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    nxci_ctx_t tool_ctx;
    char input_name[0x200];
    char rename_target[MAX_PATH] = {0};

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("4NXCI %s by The-4n\n", NXCI_VERSION);

    memset(&tool_ctx, 0, sizeof(tool_ctx));
    memset(input_name, 0, sizeof(input_name));
    memset(&applications_cnmt_ctx, 0, sizeof(cnmts_ctx_t));
    memset(&application_nsps, 0, sizeof(application_nsps));
    memset(&patches_cnmt_ctx, 0, sizeof(cnmts_ctx_t));
    memset(&patch_nsps, 0, sizeof(patch_nsps));
    memset(&addons_cnmt_ctx, 0, sizeof(cnmts_ctx_t));
    memset(&addon_nsps, 0, sizeof(addon_nsps));

    filepath_t keypath;
    filepath_init(&keypath);

    pki_initialize_keyset(&tool_ctx.settings.keyset);

    // Hardcode secure partition save path to "4nxci_extracted_nsp" directory
    filepath_init(&tool_ctx.settings.secure_dir_path);
    filepath_set(&tool_ctx.settings.secure_dir_path, "4nxci_extracted_xci");

    // Parse options
    while (1)
    {
        int option_index;
        int c;
        static struct option long_options[] =
            {
                {"keyset", 1, NULL, 'k'},
                {"help", 0, NULL, 'h'},
                {"convert", 0, NULL, 'c'},
                {"delete", 0, NULL, 'd'},
                {"rename", 1, NULL, 'r'},
                {"tempdir", 1, NULL, 't'},
                {"outdir", 1, NULL, 'o'},
                {"keepncaid", 0, NULL, 1},
                {NULL, 0, NULL, 0},
            };

        c = getopt_long(argc, argv, "k:t:o:hcdr:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'k':
            filepath_set(&keypath, optarg);
            break;
        case 'h':
            usage();
            break;
        case 'c':
            tool_ctx.settings.titlename = 1;
            break;
        case 'd':
            tool_ctx.settings.deletexci = 1;
            break;
        case 'r':
            // Save rename path; the function is called after keys are loaded
            strncpy(rename_target, optarg, MAX_PATH - 1);
            rename_target[MAX_PATH - 1] = '\0';
            break;
        case 't':
            filepath_set(&tool_ctx.settings.secure_dir_path, optarg);
            break;
        case 'o':
            filepath_init(&tool_ctx.settings.out_dir_path);
            filepath_set(&tool_ctx.settings.out_dir_path, optarg);
            break;
        case 1:
            tool_ctx.settings.keepncaid = 1;
            break;
        default:
            usage();
        }
    }

    // Locating default key file
    FILE *keyfile = NULL;
    keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
    if (keypath.valid == VALIDITY_INVALID)
    {
        filepath_set(&keypath, "keys.dat");
        keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
        if (keyfile == NULL)
        {
            filepath_set(&keypath, "keys.txt");
            keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
        }
        if (keyfile == NULL)
        {
            filepath_set(&keypath, "keys.ini");
            keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
        }
        if (keyfile == NULL)
        {
            filepath_set(&keypath, "prod.keys");
            keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
        }
    }

    // Try to populate default keyfile.
    if (keyfile != NULL)
    {
        printf("\nLoading '%s' keyset file\n", keypath.char_path);
        extkeys_initialize_keyset(&tool_ctx.settings.keyset, keyfile);
        pki_derive_keys(&tool_ctx.settings.keyset);
        fclose(keyfile);

        if (rename_target[0] != '\0')
            return process_nsp_rename(rename_target, &tool_ctx);
    }
    else
    {
        if (rename_target[0] != '\0')
        {
            // No keyset found - NCA decryption will not be available, but
            // the .cnmt.xml and ticket fallbacks can still work without keys.
            printf("\nWarning: No keyset found - NCA decryption unavailable for rename\n");
            return process_nsp_rename(rename_target, &tool_ctx);
        }
        printf("\n");
        fprintf(stderr, "Error: Unable to open keyset file\n"
                        "Use -k or --keyset to specify your keyset file path or place your keyset in ." OS_PATH_SEPARATOR "keys.dat\n");
        return EXIT_FAILURE;
    }

    // Copy input file
    if (optind == argc - 1)
        strncpy(input_name, argv[optind], sizeof(input_name));
    else if ((optind < argc) || (argc == 1))
        usage();

    if (!(tool_ctx.file = fopen(input_name, "rb")))
    {
        fprintf(stderr, "unable to open %s: %s\n", input_name, strerror(errno));
        return EXIT_FAILURE;
    }

#ifdef _WIN32
    // Check file size and available memory
    uint64_t xci_file_size = get_file_size(tool_ctx.file);
    uint64_t available_mem = get_available_memory();

    printf("\nXCI File Size: %.2f GB\n", xci_file_size / (1024.0 * 1024.0 * 1024.0));
    printf("Available RAM: %.2f GB\n", available_mem / (1024.0 * 1024.0 * 1024.0));

    // If we have enough RAM (file size + 4GB headroom), suggest loading to RAM
    if (available_mem > xci_file_size + (4ULL * 1024 * 1024 * 1024))
    {
        printf("Note: Sufficient RAM available for optimal performance\n");
    }
    else
    {
        printf("Note: Limited RAM - using disk-based processing\n");
    }
#endif

    /* Set large buffer for input XCI file to dramatically improve read performance */
    static unsigned char xci_file_buffer[16 * 1024 * 1024]; /* 16MB static buffer for input file */
    setvbuf(tool_ctx.file, (char*)xci_file_buffer, _IOFBF, sizeof(xci_file_buffer));

    xci_ctx_t xci_ctx;
    memset(&xci_ctx, 0, sizeof(xci_ctx));
    xci_ctx.file = tool_ctx.file;
    xci_ctx.tool_ctx = &tool_ctx;

    // Remove existing temp directory
    filepath_remove_directory(&xci_ctx.tool_ctx->settings.secure_dir_path);

    // Create output directory if it's valid
    if (xci_ctx.tool_ctx->settings.out_dir_path.valid == VALIDITY_VALID)
        os_makedir(xci_ctx.tool_ctx->settings.out_dir_path.os_path);

    printf("\n");

    xci_process(&xci_ctx);

    // Process ncas in cnmts
    application_nsps = (nsp_ctx_t *)calloc(1, sizeof(nsp_ctx_t) * applications_cnmt_ctx.count);
    printf("===> Processing %u Application(s):\n", applications_cnmt_ctx.count);

#ifdef _WIN32
    // Get number of CPU cores for parallel processing
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    int num_cores = sysinfo.dwNumberOfProcessors;
    printf("System has %d CPU cores - enabling parallel processing\n", num_cores);

    // Create thread pool with number of cores (or half if very large XCI)
    int thread_count = num_cores;
    if (thread_count > 8) thread_count = 8;  // Cap at 8 threads to avoid overhead

    threadpool_t *pool = threadpool_create(thread_count);
    if (pool == NULL) {
        fprintf(stderr, "Warning: Failed to create thread pool, falling back to single-threaded\n");
        thread_count = 0;  // Fall back to sequential processing
    } else {
        printf("Created thread pool with %d worker threads\n", thread_count);
    }
#else
    threadpool_t *pool = NULL;
    int thread_count = 0;
#endif

    // Process applications in parallel (if thread pool available)
    if (pool != NULL && applications_cnmt_ctx.count > 0) {
        for (int apppc = 0; apppc < applications_cnmt_ctx.count; apppc++)
        {
            printf("===> Queuing Application %i Metadata for processing\n", apppc + 1);

            process_task_t *task = (process_task_t *)malloc(sizeof(process_task_t));
            task->tool_ctx = xci_ctx.tool_ctx;
            task->cnmt_xml = &applications_cnmt_ctx.cnmt_xml[apppc];
            task->cnmt = &applications_cnmt_ctx.cnmt[apppc];
            task->nsp = &application_nsps[apppc];
            task->index = apppc;
            task->type = 0;

            if (threadpool_add_task(pool, process_gamecard_worker, task) != 0) {
                fprintf(stderr, "Warning: Failed to queue task, processing synchronously\n");
                process_gamecard_worker(task);
            }
        }

        // Wait for all application tasks to complete
        printf("Waiting for application processing to complete...\n");
        threadpool_wait(pool);
        printf("All applications processed!\n");
    } else {
        // Sequential fallback
        for (int apppc = 0; apppc < applications_cnmt_ctx.count; apppc++)
        {
            printf("===> Processing Application %i Metadata:\n", apppc + 1);
            cnmt_gamecard_process(xci_ctx.tool_ctx, &applications_cnmt_ctx.cnmt_xml[apppc], &applications_cnmt_ctx.cnmt[apppc], &application_nsps[apppc]);
        }
    }

    if (patches_cnmt_ctx.count != 0)
    {
        patch_nsps = (nsp_ctx_t *)calloc(1, sizeof(nsp_ctx_t) * patches_cnmt_ctx.count);
        printf("===> Processing %u Patch(es):\n", patches_cnmt_ctx.count);

        if (pool != NULL) {
            for (int patchpc = 0; patchpc < patches_cnmt_ctx.count; patchpc++)
            {
                printf("===> Queuing Patch %i Metadata for processing\n", patchpc + 1);

                process_task_t *task = (process_task_t *)malloc(sizeof(process_task_t));
                task->tool_ctx = xci_ctx.tool_ctx;
                task->cnmt_xml = &patches_cnmt_ctx.cnmt_xml[patchpc];
                task->cnmt = &patches_cnmt_ctx.cnmt[patchpc];
                task->nsp = &patch_nsps[patchpc];
                task->index = patchpc;
                task->type = 1;

                if (threadpool_add_task(pool, process_download_worker, task) != 0) {
                    fprintf(stderr, "Warning: Failed to queue task, processing synchronously\n");
                    process_download_worker(task);
                }
            }

            printf("Waiting for patch processing to complete...\n");
            threadpool_wait(pool);
            printf("All patches processed!\n");
        } else {
            for (int patchpc = 0; patchpc < patches_cnmt_ctx.count; patchpc++)
            {
                printf("===> Processing Patch %i Metadata:\n", patchpc + 1);
                cnmt_download_process(xci_ctx.tool_ctx, &patches_cnmt_ctx.cnmt_xml[patchpc], &patches_cnmt_ctx.cnmt[patchpc], &patch_nsps[patchpc]);
            }
        }
    }

    if (addons_cnmt_ctx.count != 0)
    {
        addon_nsps = (nsp_ctx_t *)calloc(1, sizeof(nsp_ctx_t) * addons_cnmt_ctx.count);
        printf("===> Processing %u Addon(s):\n", addons_cnmt_ctx.count);

        if (pool != NULL) {
            for (int addpc = 0; addpc < addons_cnmt_ctx.count; addpc++)
            {
                printf("===> Queuing AddOn %i Metadata for processing\n", addpc + 1);

                process_task_t *task = (process_task_t *)malloc(sizeof(process_task_t));
                task->tool_ctx = xci_ctx.tool_ctx;
                task->cnmt_xml = &addons_cnmt_ctx.cnmt_xml[addpc];
                task->cnmt = &addons_cnmt_ctx.cnmt[addpc];
                task->nsp = &addon_nsps[addpc];
                task->index = addpc;
                task->type = 2;

                if (threadpool_add_task(pool, process_gamecard_worker, task) != 0) {
                    fprintf(stderr, "Warning: Failed to queue task, processing synchronously\n");
                    process_gamecard_worker(task);
                }
            }

            printf("Waiting for addon processing to complete...\n");
            threadpool_wait(pool);
            printf("All addons processed!\n");
        } else {
            for (int addpc = 0; addpc < addons_cnmt_ctx.count; addpc++)
            {
                printf("===> Processing AddOn %i Metadata:\n", addpc + 1);
                cnmt_gamecard_process(xci_ctx.tool_ctx, &addons_cnmt_ctx.cnmt_xml[addpc], &addons_cnmt_ctx.cnmt[addpc], &addon_nsps[addpc]);
            }
        }
    }

    // Destroy thread pool
    if (pool != NULL) {
        threadpool_destroy(pool);
        printf("Thread pool cleaned up\n");
    }

    filepath_remove_directory(&xci_ctx.tool_ctx->settings.secure_dir_path);

    printf("\n===> Renaming NSP files...\n");
    printf("DEBUG: Applications count: %u\n", applications_cnmt_ctx.count);

    // Rename NSP files with title prefix and appropriate suffixes
    for (int i = 0; i < applications_cnmt_ctx.count; i++)
    {
        printf("DEBUG: Processing application %d\n", i);
        printf("DEBUG: Title name: '%s'\n", application_nsps[i].title_name);
        printf("DEBUG: Current path: '%s'\n", application_nsps[i].filepath.char_path);

        if (strlen(application_nsps[i].title_name) == 0)
        {
            printf("DEBUG: Skipping - empty title name\n");
            continue;
        }

        char old_path[MAX_PATH];
        char new_path[MAX_PATH];
        char dir_path[MAX_PATH] = "";
        char title_id[MAX_PATH];

        strncpy(old_path, application_nsps[i].filepath.char_path, MAX_PATH - 1);
        old_path[MAX_PATH - 1] = '\0';

        // Get title ID from cnmt_xml instead of extracting from filename
        // This is needed when -r flag is used (filename is title name, not ID)
        sprintf(title_id, "%016llX", (unsigned long long)applications_cnmt_ctx.cnmt[i].title_id);

        printf("DEBUG: Title ID from cnmt: '%s'\n", title_id);

        // Extract directory path
        char *last_sep = strrchr(old_path, PATH_SEPERATOR);

        if (last_sep != NULL)
        {
            size_t dir_len = last_sep - old_path + 1;
            strncpy(dir_path, old_path, dir_len);
            dir_path[dir_len] = '\0';

            printf("DEBUG: dir_path: '%s'\n", dir_path);
        }
        else
        {
            printf("DEBUG: No directory separator found\n");
        }

        // Build new filename
        build_nsp_filename(new_path, MAX_PATH, dir_path, application_nsps[i].title_name, title_id, "[BASE]", ".nsp");

        printf("Renaming: %s\n       -> %s\n", old_path, new_path);

        // Check if file exists
        FILE *test = fopen(old_path, "rb");
        if (test)
        {
            fclose(test);
            printf("DEBUG: File exists at old_path\n");
        }
        else
        {
            printf("DEBUG: WARNING - File does NOT exist at old_path!\n");
        }

        if (move_file_robust(old_path, new_path) == 0)
        {
            filepath_set(&application_nsps[i].filepath, new_path);
            printf("DEBUG: Rename successful!\n");
        }
        else
        {
            fprintf(stderr, "Warning: Failed to rename %s (errno: %d - %s)\n", 
                    old_path, errno, strerror(errno));
        }
    }

    if (patches_cnmt_ctx.count != 0)
    {
        for (int i = 0; i < patches_cnmt_ctx.count; i++)
        {
            if (applications_cnmt_ctx.count == 0 || strlen(application_nsps[0].title_name) == 0)
                continue;

            char old_path[MAX_PATH];
            char new_path[MAX_PATH];
            char dir_path[MAX_PATH] = "";
            char title_id[MAX_PATH];

            strncpy(old_path, patch_nsps[i].filepath.char_path, MAX_PATH - 1);
            old_path[MAX_PATH - 1] = '\0';

            // Get title ID from cnmt instead of filename
            sprintf(title_id, "%016llX", (unsigned long long)patches_cnmt_ctx.cnmt[i].title_id);

            char *last_sep = strrchr(old_path, PATH_SEPERATOR);

            if (last_sep != NULL)
            {
                size_t dir_len = last_sep - old_path + 1;
                strncpy(dir_path, old_path, dir_len);
                dir_path[dir_len] = '\0';
            }

            // Build new filename with version: Title[TitleID][vVersion][UPD].nsp
            char suffix[64];

            // Use raw version number instead of decoded semantic version
            if (patches_cnmt_ctx.cnmt[i].title_version > 0)
            {
                snprintf(suffix, sizeof(suffix), "[v%u][UPD]", patches_cnmt_ctx.cnmt[i].title_version);
            }
            else
            {
                strcpy(suffix, "[UPD]");
            }

            build_nsp_filename(new_path, MAX_PATH, dir_path, application_nsps[0].title_name, title_id, suffix, ".nsp");

            printf("Renaming: %s\n       -> %s\n", old_path, new_path);

            if (move_file_robust(old_path, new_path) == 0)
            {
                filepath_set(&patch_nsps[i].filepath, new_path);
            }
            else
            {
                fprintf(stderr, "Warning: Failed to rename %s\n", old_path);
            }
        }
    }

    if (addons_cnmt_ctx.count != 0)
    {
        for (int i = 0; i < addons_cnmt_ctx.count; i++)
        {
            if (applications_cnmt_ctx.count == 0 || strlen(application_nsps[0].title_name) == 0)
                continue;

            char old_path[MAX_PATH];
            char new_path[MAX_PATH];
            char dir_path[MAX_PATH] = "";
            char title_id[MAX_PATH];

            strncpy(old_path, addon_nsps[i].filepath.char_path, MAX_PATH - 1);
            old_path[MAX_PATH - 1] = '\0';

            // Get title ID from cnmt instead of filename
            sprintf(title_id, "%016llX", (unsigned long long)addons_cnmt_ctx.cnmt[i].title_id);

            char *last_sep = strrchr(old_path, PATH_SEPERATOR);

            if (last_sep != NULL)
            {
                size_t dir_len = last_sep - old_path + 1;
                strncpy(dir_path, old_path, dir_len);
                dir_path[dir_len] = '\0';
            }

            build_nsp_filename(new_path, MAX_PATH, dir_path, application_nsps[0].title_name, title_id, "[DLC]", ".nsp");

            printf("Renaming: %s\n       -> %s\n", old_path, new_path);

            if (move_file_robust(old_path, new_path) == 0)
            {
                filepath_set(&addon_nsps[i].filepath, new_path);
            }
            else
            {
                fprintf(stderr, "Warning: Failed to rename %s\n", old_path);
            }
        }
    }

    printf("\nSummary:\n");
    for (int gsum = 0; gsum < applications_cnmt_ctx.count; gsum++)
        printf("Game NSP %i: %s\n", gsum + 1, application_nsps[gsum].filepath.char_path);
    if (patches_cnmt_ctx.count != 0)
    {
        for (int patchsum = 0; patchsum < patches_cnmt_ctx.count; patchsum++)
            printf("Update NSP: %i: %s\n", patchsum + 1, patch_nsps[patchsum].filepath.char_path);
    }
    if (addons_cnmt_ctx.count != 0)
    {
        for (int dlcsum = 0; dlcsum < addons_cnmt_ctx.count; dlcsum++)
            printf("DLC NSP %i: %s\n", dlcsum + 1, addon_nsps[dlcsum].filepath.char_path);
    }

    // Create folder based on game title name and move all files
    if (applications_cnmt_ctx.count > 0 && strlen(application_nsps[0].title_name) > 0)
    {
        filepath_t game_folder;
        filepath_init(&game_folder);

        // Extract the directory where the XCI file is located
        char xci_directory[MAX_PATH] = "";
        char *xci_last_sep = strrchr(input_name, PATH_SEPERATOR);

        if (xci_last_sep != NULL)
        {
            // XCI has a directory path - extract it
            size_t xci_dir_len = xci_last_sep - input_name;
            strncpy(xci_directory, input_name, xci_dir_len);
            xci_directory[xci_dir_len] = '\0';
        }
        else
        {
            // XCI is in current directory
            strcpy(xci_directory, ".");
        }

        // Create temporary game folder in output directory (or current dir)
        filepath_t temp_game_folder;
        filepath_init(&temp_game_folder);

        if (xci_ctx.tool_ctx->settings.out_dir_path.valid == VALIDITY_VALID)
        {
            filepath_copy(&temp_game_folder, &xci_ctx.tool_ctx->settings.out_dir_path);
            filepath_append(&temp_game_folder, "%s", application_nsps[0].title_name);
        }
        else
        {
            filepath_set(&temp_game_folder, application_nsps[0].title_name);
        }

        // Create the temporary game folder
        printf("\n===> Creating folder: %s\n", temp_game_folder.char_path);
        if (os_makedir(temp_game_folder.os_path) != 0)
        {
            fprintf(stderr, "Warning: Failed to create folder %s\n", temp_game_folder.char_path);
        }

        // Move all application NSPs
        printf("\n===> Moving files to game folder...\n");
        for (int i = 0; i < applications_cnmt_ctx.count; i++)
        {
            char *filename = strrchr(application_nsps[i].filepath.char_path, PATH_SEPERATOR);
            if (filename == NULL)
                filename = application_nsps[i].filepath.char_path;
            else
                filename++;

            filepath_t new_nsp_path;
            filepath_copy(&new_nsp_path, &temp_game_folder);
            filepath_append(&new_nsp_path, "%s", filename);

            printf("Moving: %s\n     -> %s\n", application_nsps[i].filepath.char_path, new_nsp_path.char_path);
            if (move_file_robust(application_nsps[i].filepath.char_path, new_nsp_path.char_path) != 0)
            {
                fprintf(stderr, "Warning: Failed to move %s (Error: %s)\n", 
                        application_nsps[i].filepath.char_path, strerror(errno));
            }
        }

        // Move all patch NSPs
        if (patches_cnmt_ctx.count != 0)
        {
            for (int i = 0; i < patches_cnmt_ctx.count; i++)
            {
                char *filename = strrchr(patch_nsps[i].filepath.char_path, PATH_SEPERATOR);
                if (filename == NULL)
                    filename = patch_nsps[i].filepath.char_path;
                else
                    filename++;

                filepath_t new_nsp_path;
                filepath_copy(&new_nsp_path, &temp_game_folder);
                filepath_append(&new_nsp_path, "%s", filename);

                printf("Moving: %s\n     -> %s\n", patch_nsps[i].filepath.char_path, new_nsp_path.char_path);
                if (move_file_robust(patch_nsps[i].filepath.char_path, new_nsp_path.char_path) != 0)
                {
                    fprintf(stderr, "Warning: Failed to move %s (Error: %s)\n", 
                            patch_nsps[i].filepath.char_path, strerror(errno));
                }
            }
        }

        // Move all addon NSPs
        if (addons_cnmt_ctx.count != 0)
        {
            for (int i = 0; i < addons_cnmt_ctx.count; i++)
            {
                char *filename = strrchr(addon_nsps[i].filepath.char_path, PATH_SEPERATOR);
                if (filename == NULL)
                    filename = addon_nsps[i].filepath.char_path;
                else
                    filename++;

                filepath_t new_nsp_path;
                filepath_copy(&new_nsp_path, &temp_game_folder);
                filepath_append(&new_nsp_path, "%s", filename);

                printf("Moving: %s\n     -> %s\n", addon_nsps[i].filepath.char_path, new_nsp_path.char_path);
                if (move_file_robust(addon_nsps[i].filepath.char_path, new_nsp_path.char_path) != 0)
                {
                    fprintf(stderr, "Warning: Failed to move %s (Error: %s)\n", 
                            addon_nsps[i].filepath.char_path, strerror(errno));
                }
            }
        }

        // Close the XCI file
        fclose(tool_ctx.file);

        // Delete the XCI file if -d flag is set
        if (tool_ctx.settings.deletexci)
        {
            printf("\n===> Deleting source XCI file...\n");
            printf("Deleting: %s\n", input_name);

            if (remove(input_name) == 0)
            {
                printf("Successfully deleted XCI file\n");
            }
            else
            {
                fprintf(stderr, "Warning: Failed to delete XCI file %s (Error: %s)\n", 
                        input_name, strerror(errno));
            }
        }
        else
        {
            printf("\nSource XCI file kept: %s\n", input_name);
        }

        // Move the game folder to where the XCI was located
        filepath_init(&game_folder);
        if (strlen(xci_directory) > 0 && strcmp(xci_directory, ".") != 0)
        {
            filepath_set(&game_folder, xci_directory);
            filepath_append(&game_folder, "%s", application_nsps[0].title_name);
        }
        else
        {
            filepath_set(&game_folder, application_nsps[0].title_name);
        }

        // Only move if the destination is different from current location
        if (strcmp(temp_game_folder.char_path, game_folder.char_path) != 0)
        {
            printf("\n===> Moving game folder to XCI location...\n");
            printf("Moving: %s\n     -> %s\n", temp_game_folder.char_path, game_folder.char_path);

            if (move_file_robust(temp_game_folder.char_path, game_folder.char_path) == 0)
            {
                printf("Successfully moved game folder to XCI location\n");
            }
            else
            {
                fprintf(stderr, "Warning: Failed to move game folder (Error: %s)\n", strerror(errno));
                printf("Game folder remains at: %s\n", temp_game_folder.char_path);
            }
        }
        else
        {
            printf("\nGame folder is already at XCI location: %s\n", game_folder.char_path);
        }
    }
    else
    {
        fclose(tool_ctx.file);
    }
    printf("\nDone!\n");
    return EXIT_SUCCESS;
}
