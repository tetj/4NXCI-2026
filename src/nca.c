#include <stdlib.h>
#include <stdio.h>
#ifndef _MSC_VER
#include <libgen.h>
#endif
#include <inttypes.h>
#include "nca.h"
#include "aes.h"
#include "pki.h"
#include "sha.h"
#include "rsa.h"
#include "romfs.h"
#include "utils.h"
#include "extkeys.h"
#include "filepath.h"

#ifdef _MSC_VER
// Windows implementation of basename
static char* basename(char* path) {
    char* base = strrchr(path, '\\');
    if (!base) base = strrchr(path, '/');
    return base ? base + 1 : path;
}
#endif

/* Initialize the context. */
void nca_init(nca_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void nca_free_section_contexts(nca_ctx_t *ctx)
{
    for (unsigned int i = 0; i < 4; i++)
    {
        if (ctx->section_contexts[i].is_present)
        {
            if (ctx->section_contexts[i].aes)
            {
                free_aes_ctx(ctx->section_contexts[i].aes);
            }
            if (ctx->section_contexts[i].type == PFS0 && ctx->section_contexts[i].pfs0_ctx.is_exefs)
            {
                free(ctx->section_contexts[i].pfs0_ctx.npdm);
            }
            else if (ctx->section_contexts[i].type == ROMFS)
            {
                if (ctx->section_contexts[i].romfs_ctx.directories)
                {
                    free(ctx->section_contexts[i].romfs_ctx.directories);
                }
                if (ctx->section_contexts[i].romfs_ctx.files)
                {
                    free(ctx->section_contexts[i].romfs_ctx.files);
                }
            }
            else if (ctx->section_contexts[i].type == BKTR)
            {
                if (ctx->section_contexts[i].bktr_ctx.subsection_block)
                {
                    free(ctx->section_contexts[i].bktr_ctx.subsection_block);
                }
                if (ctx->section_contexts[i].bktr_ctx.relocation_block)
                {
                    free(ctx->section_contexts[i].bktr_ctx.relocation_block);
                }
                if (ctx->section_contexts[i].bktr_ctx.directories)
                {
                    free(ctx->section_contexts[i].bktr_ctx.directories);
                }
                if (ctx->section_contexts[i].bktr_ctx.files)
                {
                    free(ctx->section_contexts[i].bktr_ctx.files);
                }
            }
        }
    }
}

/* Updates the CTR for an offset. */
void nca_update_ctr(unsigned char *ctr, uint64_t ofs)
{
    ofs >>= 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }
}

/* Seek to an offset within a section. */
void nca_section_fseek(nca_section_ctx_t *ctx, uint64_t offset)
{
    fseeko64(ctx->file, (ctx->offset + offset) & ~0xF, SEEK_SET);
    ctx->cur_seek = (ctx->offset + offset) & ~0xF;
    nca_update_ctr(ctx->ctr, ctx->offset + offset);
    ctx->sector_ofs = offset & 0xF;
}

// Read and decrypt part of section into a buff
size_t nca_section_fread(nca_section_ctx_t *ctx, void *buffer, size_t count)
{
    size_t read = 0; /* XXX */
    char block_buf[0x10];
    if (ctx->sector_ofs)
    {
        if ((read = fread(block_buf, 1, 0x10, ctx->file)) != 0x10)
        {
            return 0;
        }
        aes_setiv(ctx->aes, ctx->ctr, 0x10);
        aes_decrypt(ctx->aes, block_buf, block_buf, 0x10);
        if (count + ctx->sector_ofs < 0x10)
        {
            memcpy(buffer, block_buf + ctx->sector_ofs, count);
            ctx->sector_ofs += count;
            nca_section_fseek(ctx, ctx->cur_seek - ctx->offset);
            return count;
        }
        memcpy(buffer, block_buf + ctx->sector_ofs, 0x10 - ctx->sector_ofs);
        uint32_t read_in_block = 0x10 - ctx->sector_ofs;
        nca_section_fseek(ctx, ctx->cur_seek - ctx->offset + 0x10);
        return read_in_block + nca_section_fread(ctx, (char *)buffer + read_in_block, count - read_in_block);
    }
    if ((read = fread(buffer, 1, count, ctx->file)) != count)
    {
        return 0;
    }
    aes_setiv(ctx->aes, ctx->ctr, 16);
    aes_decrypt(ctx->aes, buffer, buffer, count);
    nca_section_fseek(ctx, ctx->cur_seek - ctx->offset + count);
    return read;
}

// Get a buff, encrypt it and write it in section
size_t nca_section_fwrite(nca_section_ctx_t *ctx, void *buffer, size_t count, uint64_t offset)
{
    nca_section_fseek(ctx, offset);
    uint8_t sector_ofs = ctx->sector_ofs;
    uint64_t temp_buff_size = sector_ofs + count;
    unsigned char *temp_buff = (unsigned char *)malloc(temp_buff_size);
    nca_section_fseek(ctx, ctx->cur_seek - ctx->offset);
    nca_section_fread(ctx, temp_buff, sector_ofs);
    nca_section_fseek(ctx, ctx->cur_seek - ctx->offset);
    memcpy(temp_buff + sector_ofs, buffer, count);
    aes_setiv(ctx->aes, ctx->ctr, 16);
    aes_encrypt(ctx->aes, temp_buff, temp_buff, temp_buff_size);
    if (!fwrite(temp_buff, 1, temp_buff_size, ctx->file))
    {
        fprintf(stderr, "Unable to modify NCA");
        return 0;
    }
    nca_section_fseek(ctx, ctx->cur_seek - ctx->offset + count);
    return count;
}

// Rewrite modified header
static void nca_save(nca_ctx_t *ctx)
{
    fseeko64(ctx->file, 0, SEEK_SET);
    if (!fwrite(&ctx->header, 1, 0xC00, ctx->file))
    {
        fprintf(stderr, "Unable to patch NCA header");
        exit(EXIT_FAILURE);
    }
}

// Corrupt ACID sig
void nca_exefs_npdm_process(nca_ctx_t *ctx)
{
    printf("DEBUG: nca_exefs_npdm_process() - Starting\n");

    pfs0_header_t pfs0_header;
    npdm_t npdm_header;
    uint64_t pfs0_start_offset = 0;
    uint64_t file_entry_table_offset = 0;
    uint64_t file_entry_table_size = 0;
    uint64_t meta_offset = 0;
    uint64_t acid_offset = 0;
    uint64_t raw_data_offset = 0;
    uint64_t file_raw_data_offset = 0;
    uint64_t block_start_offset = 0;
    uint64_t block_hash_table_offset = 0;

    printf("DEBUG: nca_exefs_npdm_process() - Decrypting key area...\n");
    nca_decrypt_key_area(ctx);
    printf("DEBUG: nca_exefs_npdm_process() - Key area decrypted\n");

    // Looking for main.npdm / META
    printf("DEBUG: nca_exefs_npdm_process() - Setting up section context...\n");
    ctx->section_contexts[0].aes = new_aes_ctx(ctx->decrypted_keys[2], 16, AES_MODE_CTR);
    ctx->section_contexts[0].offset = media_to_real(ctx->header.section_entries[0].media_start_offset);
    ctx->section_contexts[0].sector_ofs = 0;
    ctx->section_contexts[0].file = ctx->file;
    ctx->section_contexts[0].crypt_type = CRYPT_CTR;
    ctx->section_contexts[0].header = &ctx->header.fs_headers[0];

    // Calculate counter for section decryption
    printf("DEBUG: nca_exefs_npdm_process() - Calculating CTR...\n");
    uint64_t ofs = ctx->section_contexts[0].offset >> 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctx->section_contexts[0].ctr[j] = ctx->section_contexts[0].header->section_ctr[0x8 - j - 1];
        ctx->section_contexts[0].ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }
    printf("DEBUG: nca_exefs_npdm_process() - CTR calculated\n");

    // Read and decrypt PFS0 header
    printf("DEBUG: nca_exefs_npdm_process() - Reading PFS0 header...\n");
    pfs0_start_offset = ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
    printf("DEBUG: nca_exefs_npdm_process() - PFS0 offset: %llu\n", (unsigned long long)pfs0_start_offset);
    nca_section_fseek(&ctx->section_contexts[0], pfs0_start_offset);
    nca_section_fread(&ctx->section_contexts[0], &pfs0_header, sizeof(pfs0_header_t));
    printf("DEBUG: nca_exefs_npdm_process() - PFS0 header read, num_files: %d\n", pfs0_header.num_files);

    // **BUG FIX: Validate num_files to prevent infinite loop**
    if (pfs0_header.num_files <= 0 || pfs0_header.num_files > 1000) {
        fprintf(stderr, "ERROR: Invalid PFS0 header! num_files = %d (expected 1-1000)\n", pfs0_header.num_files);
        fprintf(stderr, "This usually means:\n");
        fprintf(stderr, "  1. Corrupted XCI file\n");
        fprintf(stderr, "  2. Wrong decryption keys\n");
        fprintf(stderr, "  3. Unsupported NCA format\n");
        fprintf(stderr, "Skipping ACID patching for this NCA (might still work).\n");
        return;  // Skip ACID patching but continue processing
    }
    printf("DEBUG: nca_exefs_npdm_process() - num_files validated: %d\n", pfs0_header.num_files);

    // Read and decrypt file entry table
    printf("DEBUG: nca_exefs_npdm_process() - Reading file entry table...\n");
    file_entry_table_offset = pfs0_start_offset + sizeof(pfs0_header_t);
    file_entry_table_size = sizeof(pfs0_file_entry_t) * pfs0_header.num_files;
    pfs0_file_entry_t *pfs0_file_entry_table = (pfs0_file_entry_t *)malloc(file_entry_table_size);
    nca_section_fseek(&ctx->section_contexts[0], file_entry_table_offset);
    nca_section_fread(&ctx->section_contexts[0], pfs0_file_entry_table, file_entry_table_size);
    printf("DEBUG: nca_exefs_npdm_process() - File entry table read\n");

    // Looking for META magic
    printf("DEBUG: nca_exefs_npdm_process() - Searching for META magic in %d files...\n", pfs0_header.num_files);
    uint32_t magic = 0;
    raw_data_offset = file_entry_table_offset + file_entry_table_size + pfs0_header.string_table_size;
    for (unsigned int i2 = 0; i2 < pfs0_header.num_files; i2++)
    {
        printf("DEBUG: nca_exefs_npdm_process() - Checking file %d/%d...\n", i2 + 1, pfs0_header.num_files);
        file_raw_data_offset = raw_data_offset + pfs0_file_entry_table[i2].offset;
        nca_section_fseek(&ctx->section_contexts[0], file_raw_data_offset);
        nca_section_fread(&ctx->section_contexts[0], &magic, sizeof(magic));
        printf("DEBUG: nca_exefs_npdm_process() - File %d magic: 0x%08X (looking for 0x%08X)\n", 
               i2 + 1, magic, MAGIC_META);

        if (magic == MAGIC_META)
        {
            printf("DEBUG: nca_exefs_npdm_process() - Found META magic in file %d!\n", i2 + 1);

            // Read and decrypt npdm header
            printf("DEBUG: nca_exefs_npdm_process() - Reading NPDM header...\n");
            meta_offset = file_raw_data_offset;
            nca_section_fseek(&ctx->section_contexts[0], meta_offset);
            nca_section_fread(&ctx->section_contexts[0], &npdm_header, sizeof(npdm_t));
            printf("DEBUG: nca_exefs_npdm_process() - NPDM header read, ACID offset: 0x%X\n", npdm_header.acid_offset);

            // Mix some water with acid (Corrupt ACID sig)
            printf("DEBUG: nca_exefs_npdm_process() - Corrupting ACID signature...\n");
            acid_offset = meta_offset + npdm_header.acid_offset;
            uint8_t acid_sig_byte = 0;
            nca_section_fseek(&ctx->section_contexts[0], acid_offset);
            nca_section_fread(&ctx->section_contexts[0], &acid_sig_byte, 1);
            printf("DEBUG: nca_exefs_npdm_process() - Original ACID sig byte: 0x%02X\n", acid_sig_byte);
            if (acid_sig_byte == 0xFF)
                acid_sig_byte -= 0x01;
            else
                acid_sig_byte += 0x01;
            printf("DEBUG: nca_exefs_npdm_process() - Modified ACID sig byte: 0x%02X\n", acid_sig_byte);
            nca_section_fwrite(&ctx->section_contexts[0], &acid_sig_byte, 0x01, acid_offset);
            printf("DEBUG: nca_exefs_npdm_process() - ACID signature written\n");

            // Calculate new block hash
            printf("DEBUG: nca_exefs_npdm_process() - Calculating block hash...\n");
            block_hash_table_offset = (0x20 * ((acid_offset - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset) / ctx->header.fs_headers[0].pfs0_superblock.block_size)) + ctx->header.fs_headers[0].pfs0_superblock.hash_table_offset;
            block_start_offset = (((acid_offset - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset) / ctx->header.fs_headers[0].pfs0_superblock.block_size) * ctx->header.fs_headers[0].pfs0_superblock.block_size) + ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;

            uint64_t block_size = ctx->header.fs_headers[0].pfs0_superblock.block_size;
            printf("DEBUG: nca_exefs_npdm_process() - Block size: %llu bytes\n", (unsigned long long)block_size);
            printf("DEBUG: nca_exefs_npdm_process() - Allocating block data buffer...\n");

            unsigned char *block_data = (unsigned char *)malloc(block_size);
            unsigned char *block_hash = (unsigned char *)malloc(0x20);

            printf("DEBUG: nca_exefs_npdm_process() - Reading block data at offset %llu...\n", (unsigned long long)block_start_offset);
            nca_section_fseek(&ctx->section_contexts[0], block_start_offset);
            nca_section_fread(&ctx->section_contexts[0], block_data, block_size);
            printf("DEBUG: nca_exefs_npdm_process() - Block data read, calculating SHA256...\n");

            sha_ctx_t *pfs0_sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
            sha_update(pfs0_sha_ctx, block_data, block_size);
            sha_get_hash(pfs0_sha_ctx, block_hash);
            printf("DEBUG: nca_exefs_npdm_process() - Block hash calculated, writing to hash table...\n");

            nca_section_fwrite(&ctx->section_contexts[0], block_hash, 0x20, block_hash_table_offset);
            printf("DEBUG: nca_exefs_npdm_process() - Block hash written\n");

            free(block_hash);
            free(block_data);
            free_sha_ctx(pfs0_sha_ctx);

            // Calculate PFS0 sueperblock hash
            printf("DEBUG: nca_exefs_npdm_process() - Calculating PFS0 superblock hash...\n");
            sha_ctx_t *hash_table_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
            uint64_t hash_table_size = ctx->header.fs_headers[0].pfs0_superblock.hash_table_size;
            printf("DEBUG: nca_exefs_npdm_process() - Hash table size: %llu bytes\n", (unsigned long long)hash_table_size);

            unsigned char *hash_table = (unsigned char *)malloc(hash_table_size);
            unsigned char *master_hash = (unsigned char *)malloc(0x20);

            printf("DEBUG: nca_exefs_npdm_process() - Reading hash table...\n");
            nca_section_fseek(&ctx->section_contexts[0], ctx->header.fs_headers[0].pfs0_superblock.hash_table_offset);
            nca_section_fread(&ctx->section_contexts[0], hash_table, hash_table_size);
            printf("DEBUG: nca_exefs_npdm_process() - Hash table read, updating...\n");

            sha_update(hash_table_ctx, hash_table, hash_table_size);
            sha_get_hash(hash_table_ctx, master_hash);
            memcpy(&ctx->header.fs_headers[0].pfs0_superblock.master_hash, master_hash, 0x20);
            printf("DEBUG: nca_exefs_npdm_process() - Master hash updated\n");

            free(master_hash);
            free(hash_table);
            free_sha_ctx(hash_table_ctx);

            // Calculate section hash
            printf("DEBUG: nca_exefs_npdm_process() - Calculating section hash...\n");
            unsigned char *section_hash = (unsigned char *)malloc(0x20);
            sha_ctx_t *section_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
            sha_update(section_ctx, &ctx->header.fs_headers[0], 0x200);
            sha_get_hash(section_ctx, section_hash);
            memcpy(&ctx->header.section_hashes[0], section_hash, 0x20);
            printf("DEBUG: nca_exefs_npdm_process() - Section hash calculated and updated\n");

            free(section_hash);
            free_sha_ctx(section_ctx);

            printf("DEBUG: nca_exefs_npdm_process() - META processing completed\n");
        }
    }
    free(pfs0_file_entry_table);
    printf("DEBUG: nca_exefs_npdm_process() - Completed successfully\n");
}

// Looks for title info
void nca_control_nacp_process(nca_ctx_t *ctx, nsp_ctx_t *nsp_ctx)
{
    // filepath = titleid_control.romfs
    filepath_t control_romfs_path;
    filepath_init(&control_romfs_path);
    filepath_copy(&control_romfs_path, &ctx->tool_ctx->settings.secure_dir_path);
    filepath_append(&control_romfs_path, "%016" PRIx64 "_control.romfs", ctx->header.title_id);
    printf("Extracting RomFS to %s\n", control_romfs_path.char_path);

    // Extract control.nacp

    FILE *fl;
    if (!(fl = os_fopen(control_romfs_path.os_path, OS_MODE_WRITE_EDIT)))
    {
        fprintf(stderr, "unable to create %s: %s\n", control_romfs_path.char_path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    nca_decrypt_key_area(ctx);

    ctx->section_contexts[0].aes = new_aes_ctx(ctx->decrypted_keys[2], 16, AES_MODE_CTR);
    ctx->section_contexts[0].offset = media_to_real(ctx->header.section_entries[0].media_start_offset);
    ctx->section_contexts[0].sector_ofs = 0;
    ctx->section_contexts[0].file = ctx->file;
    ctx->section_contexts[0].crypt_type = CRYPT_CTR;
    ctx->section_contexts[0].header = &ctx->header.fs_headers[0];
    
    // Calculate counter for section decryption
    uint64_t ofs = ctx->section_contexts[0].offset >> 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctx->section_contexts[0].ctr[j] = ctx->section_contexts[0].header->section_ctr[0x8 - j - 1];
        ctx->section_contexts[0].ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }

    // Seek to RomFS, decrypt and save it
    char *romfs = (char *)malloc(ctx->header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[5].hash_data_size);
    nca_section_fseek(&ctx->section_contexts[0], ctx->header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[5].logical_offset);
    nca_section_fread(&ctx->section_contexts[0], romfs, ctx->header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[5].hash_data_size);
    fwrite(romfs, ctx->header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[5].hash_data_size, 1, fl);

    fseeko64(fl, 0, SEEK_SET);
    romfs_ctx_t romfs_ctx;
    memset(&romfs_ctx, 0, sizeof(romfs_ctx_t));
    romfs_ctx.file = fl;
    romfs_process(&romfs_ctx, nsp_ctx);

    fclose(fl);
}

// Modify cnmt
void nca_cnmt_process(nca_ctx_t *ctx, cnmt_ctx_t *cnmt_ctx)
{
    pfs0_header_t pfs0_header;
    uint64_t pfs0_start_offset = 0;
    uint64_t file_entry_table_offset = 0;
    uint64_t file_entry_table_size = 0;
    uint64_t raw_data_offset = 0;
    uint64_t content_records_offset = 0;

    nca_decrypt_key_area(ctx);

    ctx->section_contexts[0].aes = new_aes_ctx(ctx->decrypted_keys[2], 16, AES_MODE_CTR);
    ctx->section_contexts[0].offset = media_to_real(ctx->header.section_entries[0].media_start_offset);
    ctx->section_contexts[0].sector_ofs = 0;
    ctx->section_contexts[0].file = ctx->file;
    ctx->section_contexts[0].crypt_type = CRYPT_CTR;
    ctx->section_contexts[0].header = &ctx->header.fs_headers[0];

    // Calculate counter for section decryption
    uint64_t ofs = ctx->section_contexts[0].offset >> 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctx->section_contexts[0].ctr[j] = ctx->section_contexts[0].header->section_ctr[0x8 - j - 1];
        ctx->section_contexts[0].ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }

    // Read and decrypt PFS0 header
    pfs0_start_offset = ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
    nca_section_fseek(&ctx->section_contexts[0], pfs0_start_offset);
    nca_section_fread(&ctx->section_contexts[0], &pfs0_header, sizeof(pfs0_header_t));

    // Write meta content records
    file_entry_table_offset = pfs0_start_offset + sizeof(pfs0_header_t);
    file_entry_table_size = sizeof(pfs0_file_entry_t) * pfs0_header.num_files;
    raw_data_offset = file_entry_table_offset + file_entry_table_size + pfs0_header.string_table_size;
    content_records_offset = raw_data_offset + sizeof(cnmt_header_t) + cnmt_ctx->extended_header_size;
    for (int i = 0; i < cnmt_ctx->nca_count; i++)
    {
        nca_section_fwrite(&ctx->section_contexts[0], &cnmt_ctx->cnmt_content_records[i], sizeof(cnmt_content_record_t), content_records_offset + (i * sizeof(cnmt_content_record_t)));
    }

    // Calculate block hash
    unsigned char *block_data = (unsigned char *)malloc(ctx->header.fs_headers[0].pfs0_superblock.pfs0_size);
    unsigned char *block_hash = (unsigned char *)malloc(0x20);
    nca_section_fseek(&ctx->section_contexts[0], ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset);
    nca_section_fread(&ctx->section_contexts[0], block_data, ctx->header.fs_headers[0].pfs0_superblock.pfs0_size);
    sha_ctx_t *pfs0_sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    sha_update(pfs0_sha_ctx, block_data, ctx->header.fs_headers[0].pfs0_superblock.pfs0_size);
    sha_get_hash(pfs0_sha_ctx, block_hash);
    nca_section_fwrite(&ctx->section_contexts[0], block_hash, 0x20, ctx->header.fs_headers[0].pfs0_superblock.hash_table_offset);
    free(block_hash);
    free(block_data);
    free_sha_ctx(pfs0_sha_ctx);

    // Calculate PFS0 sueperblock hash
    sha_ctx_t *hash_table_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    unsigned char *hash_table = (unsigned char *)malloc(ctx->header.fs_headers[0].pfs0_superblock.hash_table_size);
    unsigned char *master_hash = (unsigned char *)malloc(0x20);
    nca_section_fseek(&ctx->section_contexts[0], ctx->header.fs_headers[0].pfs0_superblock.hash_table_offset);
    nca_section_fread(&ctx->section_contexts[0], hash_table, ctx->header.fs_headers[0].pfs0_superblock.hash_table_size);
    sha_update(hash_table_ctx, hash_table, ctx->header.fs_headers[0].pfs0_superblock.hash_table_size);
    sha_get_hash(hash_table_ctx, master_hash);
    memcpy(&ctx->header.fs_headers[0].pfs0_superblock.master_hash, master_hash, 0x20);
    free(master_hash);
    free(hash_table);
    free_sha_ctx(hash_table_ctx);

    // Calculate section hash
    unsigned char *section_hash = (unsigned char *)malloc(0x20);
    sha_ctx_t *section_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    sha_update(section_ctx, &ctx->header.fs_headers[0], 0x200);
    sha_get_hash(section_ctx, section_hash);
    memcpy(&ctx->header.section_hashes[0], section_hash, 0x20);
    free(section_hash);
    free_sha_ctx(section_ctx);
}

void nca_meta_context_process(cnmt_ctx_t *cnmt_ctx, nca_ctx_t *ctx, cnmt_header_t *cnmt_header, cnmt_extended_header_t *cnmt_extended_header, uint64_t digest_offset, uint64_t content_records_start_offset, filepath_t *filepath)
{
    cnmt_ctx->nca_count = 0;
    cnmt_ctx->type = cnmt_header->type;
    cnmt_ctx->title_id = cnmt_header->title_id;
    cnmt_ctx->extended_header_patch_id = cnmt_extended_header->patch_title_id;
    cnmt_ctx->title_version = cnmt_header->title_version;
    cnmt_ctx->requiredsysversion = cnmt_extended_header->required_system_version;
    cnmt_ctx->extended_header_size = cnmt_header->extended_header_size;
    if (ctx->header.crypto_type2 > ctx->header.crypto_type)
        cnmt_ctx->keygen_min = ctx->header.crypto_type2;
    else
        cnmt_ctx->keygen_min = ctx->header.crypto_type;

    // Read content and decrypt records
    cnmt_ctx->cnmt_content_records = (cnmt_content_record_t *)malloc(sizeof(cnmt_content_record_t));
    for (int i = 0; i < cnmt_header->content_entry_count; i++)
    {
        cnmt_content_record_t temp_content_record;
        nca_section_fseek(&ctx->section_contexts[0], content_records_start_offset + (i * sizeof(cnmt_content_record_t)));
        nca_section_fread(&ctx->section_contexts[0], &temp_content_record, sizeof(cnmt_content_record_t));
        if (temp_content_record.type != 0x6) // Skip DeltaFragment
        {
            memcpy(&cnmt_ctx->cnmt_content_records[cnmt_ctx->nca_count], &temp_content_record, sizeof(cnmt_content_record_t));
            cnmt_ctx->nca_count++;
            cnmt_ctx->cnmt_content_records = (cnmt_content_record_t *)realloc(cnmt_ctx->cnmt_content_records, (cnmt_ctx->nca_count + 1) * sizeof(cnmt_content_record_t));
        }
    }

    // Get Digest, last 32 bytes of PFS0
    nca_section_fseek(&ctx->section_contexts[0], digest_offset);
    nca_section_fread(&ctx->section_contexts[0], cnmt_ctx->digest, 0x20);

    // Set meta filepath
    filepath_init(&cnmt_ctx->meta_filepath);
    filepath_copy(&cnmt_ctx->meta_filepath, filepath);
}

void nca_saved_meta_process(nca_ctx_t *ctx, filepath_t *filepath)
{
    /* Decrypt header */
    if (!nca_decrypt_header(ctx))
    {
        fprintf(stderr, "Invalid NCA header! Are keys correct?\n");
        exit(EXIT_FAILURE);
    }

    /* Sort out crypto type. */
    ctx->crypto_type = ctx->header.crypto_type;
    if (ctx->header.crypto_type2 > ctx->header.crypto_type)
        ctx->crypto_type = ctx->header.crypto_type2;
    if (ctx->crypto_type)
        ctx->crypto_type--; /* 0, 1 are both master key 0. */

    nca_decrypt_key_area(ctx);
    ctx->section_contexts[0].aes = new_aes_ctx(ctx->decrypted_keys[2], 16, AES_MODE_CTR);
    ctx->section_contexts[0].offset = media_to_real(ctx->header.section_entries[0].media_start_offset);
    ctx->section_contexts[0].sector_ofs = 0;
    ctx->section_contexts[0].file = ctx->file;
    ctx->section_contexts[0].crypt_type = CRYPT_CTR;
    ctx->section_contexts[0].header = &ctx->header.fs_headers[0];
    uint64_t ofs = ctx->section_contexts[0].offset >> 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctx->section_contexts[0].ctr[j] = ctx->section_contexts[0].header->section_ctr[0x8 - j - 1];
        ctx->section_contexts[0].ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }

    // Read and decrypt PFS0 header
    uint64_t pfs0_offset = 0;
    uint64_t pfs0_string_table_offset = 0;
    uint64_t cnmt_start_offset = 0;
    uint64_t content_records_start_offset = 0;
    cnmt_header_t cnmt_header;
    pfs0_header_t pfs0_header;
    cnmt_extended_header_t cnmt_extended_header;
    pfs0_offset = ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
    nca_section_fseek(&ctx->section_contexts[0], pfs0_offset);
    nca_section_fread(&ctx->section_contexts[0], &pfs0_header, sizeof(pfs0_header_t));

    // Read and decrypt cnmt header
    pfs0_string_table_offset = pfs0_offset + sizeof(pfs0_header_t) + (pfs0_header.num_files * sizeof(pfs0_file_entry_t));
    cnmt_start_offset = pfs0_string_table_offset + pfs0_header.string_table_size;
    nca_section_fseek(&ctx->section_contexts[0], cnmt_start_offset);
    nca_section_fread(&ctx->section_contexts[0], &cnmt_header, sizeof(cnmt_header_t));
    nca_section_fread(&ctx->section_contexts[0], &cnmt_extended_header, sizeof(cnmt_extended_header_t));

    // Read and decrypt content records
    uint64_t digest_offset = 0;
    digest_offset = pfs0_offset + ctx->header.fs_headers[0].pfs0_superblock.pfs0_size - 0x20;
    content_records_start_offset = cnmt_start_offset + sizeof(cnmt_header_t) + cnmt_header.extended_header_size;

    switch (cnmt_header.type)
    {
    case 0x80: // Application
        // Gamecard may contain more than one Application Meta
        if (applications_cnmt_ctx.count == 0)
        {
            applications_cnmt_ctx.cnmt = (cnmt_ctx_t *)calloc(1, sizeof(cnmt_ctx_t));
            applications_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)calloc(1, sizeof(cnmt_xml_ctx_t));
        }
        else
        {
            applications_cnmt_ctx.cnmt = (cnmt_ctx_t *)realloc(applications_cnmt_ctx.cnmt, (applications_cnmt_ctx.count + 1) * sizeof(cnmt_ctx_t));
            applications_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)realloc(applications_cnmt_ctx.cnmt_xml, (applications_cnmt_ctx.count + 1) * sizeof(cnmt_xml_ctx_t));
            memset(&applications_cnmt_ctx.cnmt[applications_cnmt_ctx.count], 0, sizeof(cnmt_ctx_t));
            memset(&applications_cnmt_ctx.cnmt_xml[applications_cnmt_ctx.count], 0, sizeof(cnmt_xml_ctx_t));
        }
        nca_meta_context_process(&applications_cnmt_ctx.cnmt[applications_cnmt_ctx.count], ctx, &cnmt_header, &cnmt_extended_header, digest_offset, content_records_start_offset, filepath);
        applications_cnmt_ctx.count++;
        break;
    case 0x81: // Patch
        // Gamecard may contain more than one Patch Meta
        if (patches_cnmt_ctx.count == 0)
        {
            patches_cnmt_ctx.cnmt = (cnmt_ctx_t *)calloc(1, sizeof(cnmt_ctx_t));
            patches_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)calloc(1, sizeof(cnmt_xml_ctx_t));
        }
        else
        {
            patches_cnmt_ctx.cnmt = (cnmt_ctx_t *)realloc(patches_cnmt_ctx.cnmt, (patches_cnmt_ctx.count + 1) * sizeof(cnmt_ctx_t));
            patches_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)realloc(patches_cnmt_ctx.cnmt_xml, (patches_cnmt_ctx.count + 1) * sizeof(cnmt_xml_ctx_t));
            memset(&patches_cnmt_ctx.cnmt[patches_cnmt_ctx.count], 0, sizeof(cnmt_ctx_t));
            memset(&patches_cnmt_ctx.cnmt_xml[patches_cnmt_ctx.count], 0, sizeof(cnmt_xml_ctx_t));
        }
        nca_meta_context_process(&patches_cnmt_ctx.cnmt[patches_cnmt_ctx.count], ctx, &cnmt_header, &cnmt_extended_header, digest_offset, content_records_start_offset, filepath);
        patches_cnmt_ctx.count++;
        break;
    case 0x82: // AddOn
        // Gamecard may contain more than one Addon Meta
        if (addons_cnmt_ctx.count == 0)
        {
            addons_cnmt_ctx.cnmt = (cnmt_ctx_t *)calloc(1, sizeof(cnmt_ctx_t));
            addons_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)calloc(1, sizeof(cnmt_xml_ctx_t));
        }
        else
        {
            addons_cnmt_ctx.cnmt = (cnmt_ctx_t *)realloc(addons_cnmt_ctx.cnmt, (addons_cnmt_ctx.count + 1) * sizeof(cnmt_ctx_t));
            addons_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)realloc(addons_cnmt_ctx.cnmt_xml, (addons_cnmt_ctx.count + 1) * sizeof(cnmt_xml_ctx_t));
            memset(&addons_cnmt_ctx.cnmt[addons_cnmt_ctx.count], 0, sizeof(cnmt_ctx_t));
            memset(&addons_cnmt_ctx.cnmt_xml[addons_cnmt_ctx.count], 0, sizeof(cnmt_xml_ctx_t));
        }
        nca_meta_context_process(&addons_cnmt_ctx.cnmt[addons_cnmt_ctx.count], ctx, &cnmt_header, &cnmt_extended_header, digest_offset, content_records_start_offset, filepath);
        addons_cnmt_ctx.count++;
        break;
    default:
        fprintf(stderr, "Unknown meta type! Are keys correct?\n");
        exit(EXIT_FAILURE);
    }
}

void nca_gamecard_process(nca_ctx_t *ctx, filepath_t *filepath, int index, cnmt_xml_ctx_t *cnmt_xml_ctx, cnmt_ctx_t *cnmt_ctx, nsp_ctx_t *nsp_ctx)
{
    printf("DEBUG: nca_gamecard_process() - Starting for index %d\n", index);
    printf("DEBUG: nca_gamecard_process() - Filepath: %s\n", filepath->char_path);

    /* Decrypt header */
    printf("DEBUG: nca_gamecard_process() - Decrypting NCA header...\n");
    if (!nca_decrypt_header(ctx))
    {
        fprintf(stderr, "Invalid NCA header! Are keys correct?\n");
        exit(EXIT_FAILURE);
    }
    printf("DEBUG: nca_gamecard_process() - Header decrypted successfully\n");

    uint8_t content_type = ctx->header.content_type;
    uint64_t nca_size = ctx->header.nca_size;

    printf("DEBUG: nca_gamecard_process() - Content type: %d, NCA size: %llu bytes\n", 
           content_type, (unsigned long long)nca_size);

    /* Sort out crypto type. */
    ctx->crypto_type = ctx->header.crypto_type;
    if (ctx->header.crypto_type2 > ctx->header.crypto_type)
        ctx->crypto_type = ctx->header.crypto_type2;
    if (ctx->crypto_type)
        ctx->crypto_type--; /* 0, 1 are both master key 0. */

    printf("DEBUG: nca_gamecard_process() - Crypto type determined: %d\n", ctx->crypto_type);

    // Set required values for creating .cnmt.xml
    cnmt_xml_ctx->contents[index].size = ctx->header.nca_size;
    if (ctx->header.crypto_type2 > ctx->header.crypto_type)
        cnmt_xml_ctx->contents[index].keygeneration = ctx->header.crypto_type2;
    else
        cnmt_xml_ctx->contents[index].keygeneration = ctx->header.crypto_type;
    if (content_type != 1) // Meta nca lacks of content records
        cnmt_xml_ctx->contents[index].type = cnmt_get_content_type(cnmt_ctx->cnmt_content_records[index].type);
    else
        cnmt_xml_ctx->contents[index].type = cnmt_get_content_type(0x00);

    // Patch ACID sig if nca type = program
    if (content_type == 0) // Program nca
    {
        printf("DEBUG: nca_gamecard_process() - Processing PROGRAM NCA (content_type=0)...\n");
        printf("DEBUG: nca_gamecard_process() - Calling nca_exefs_npdm_process()...\n");
        nca_exefs_npdm_process(ctx);
        printf("DEBUG: nca_gamecard_process() - nca_exefs_npdm_process() completed\n");
    }
    else if (content_type == 1) // Meta nca
    {
        printf("DEBUG: nca_gamecard_process() - Processing META NCA (content_type=1)...\n");
        printf("DEBUG: nca_gamecard_process() - Calling nca_cnmt_process()...\n");
        nca_cnmt_process(ctx, cnmt_ctx);
        printf("DEBUG: nca_gamecard_process() - nca_cnmt_process() completed\n");
    }
    else if (content_type == 2 && ctx->tool_ctx->settings.titlename == 1) // Control nca
    {
        printf("DEBUG: nca_gamecard_process() - Processing CONTROL NCA (content_type=2)...\n");
        printf("DEBUG: nca_gamecard_process() - Calling nca_control_nacp_process()...\n");
        nca_control_nacp_process(ctx, nsp_ctx);
        printf("DEBUG: nca_gamecard_process() - nca_control_nacp_process() completed\n");
    }
    else
    {
        printf("DEBUG: nca_gamecard_process() - Content type %d, no special processing needed\n", content_type);
    }

    // Set distrbution type to "System"
    printf("DEBUG: nca_gamecard_process() - Setting distribution type to System\n");
    ctx->header.distribution = 0;

    // Re-encrypt header
    printf("DEBUG: nca_gamecard_process() - Re-encrypting header...\n");
    nca_encrypt_header(ctx);
    printf("DEBUG: nca_gamecard_process() - Header re-encrypted\n");

    printf("Patching %s\n", filepath->char_path);
    printf("DEBUG: nca_gamecard_process() - Calling nca_save()...\n");
    nca_save(ctx);
    printf("DEBUG: nca_gamecard_process() - nca_save() completed\n");

    // Calculate SHA-256 hash
    printf("DEBUG: nca_gamecard_process() - Calculating SHA-256 hash (file size: %llu bytes)...\n", 
           (unsigned long long)nca_size);
    sha_ctx_t *sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    uint64_t read_size = 0x61A8000; // 100 MB buffer.
    unsigned char *buf = malloc(read_size);
    if (buf == NULL)
    {
        fprintf(stderr, "Failed to allocate file-read buffer!\n");
        exit(EXIT_FAILURE);
    }
    printf("DEBUG: nca_gamecard_process() - Allocated 100MB hash buffer\n");

    fseeko64(ctx->file, 0, SEEK_SET);
    uint64_t ofs = 0;
    uint64_t filesize = nca_size;
    int hash_iteration = 0;

    printf("DEBUG: nca_gamecard_process() - Starting hash calculation loop...\n");
    while (ofs < filesize)
    {
        hash_iteration++;
        if (hash_iteration % 10 == 0) {
            printf("DEBUG: Hash iteration %d, offset: %llu / %llu (%.1f%%)\n", 
                   hash_iteration, (unsigned long long)ofs, (unsigned long long)filesize,
                   (ofs * 100.0) / filesize);
        }

        if (ofs + read_size >= filesize)
            read_size = filesize - ofs;
        if (fread(buf, 1, read_size, ctx->file) != read_size)
        {
            fprintf(stderr, "Failed to read file!\n");
            exit(EXIT_FAILURE);
        }
        sha_update(sha_ctx, buf, read_size);
        ofs += read_size;
    }
    printf("DEBUG: nca_gamecard_process() - Hash calculation completed after %d iterations\n", hash_iteration);

    printf("DEBUG: nca_gamecard_process() - Closing NCA file...\n");
    fclose(ctx->file);
    free(buf);
    printf("DEBUG: nca_gamecard_process() - Getting hash result...\n");
    unsigned char *hash_result = (unsigned char *)calloc(1, 32);
    sha_get_hash(sha_ctx, hash_result);
    printf("DEBUG: nca_gamecard_process() - Hash obtained successfully\n");

    // Update nca hash and ncaid
    if (content_type != 1)
    {
        printf("DEBUG: nca_gamecard_process() - Updating content record hash...\n");
        memcpy(cnmt_ctx->cnmt_content_records[index].hash, hash_result, 32);
        if (ctx->tool_ctx->settings.keepncaid != 1)
            memcpy(cnmt_ctx->cnmt_content_records[index].ncaid, hash_result, 16);
    }
    free_sha_ctx(sha_ctx);
    printf("DEBUG: nca_gamecard_process() - Hash context freed\n");

    // Convert hash to hex string
    char *hash_hex = (char *)calloc(1, 65);
    hexBinaryString(hash_result, 32, hash_hex, 65);
    printf("DEBUG: nca_gamecard_process() - Hash converted to hex string\n");

    // Set hash and id for xml meta, id = first 16 bytes of hash
    strncpy(cnmt_xml_ctx->contents[index].hash, hash_hex, 64);
    cnmt_xml_ctx->contents[index].hash[64] = '\0';
    if (content_type == 1 && ctx->tool_ctx->settings.keepncaid == 1)
        strncpy(cnmt_xml_ctx->contents[index].id, basename(cnmt_ctx->meta_filepath.char_path), 32);
    else
        strncpy(cnmt_xml_ctx->contents[index].id, hash_hex, 32);
    cnmt_xml_ctx->contents[index].id[32] = '\0';
    free(hash_hex);
    free(hash_result);
    printf("DEBUG: nca_gamecard_process() - Hash and ID set in XML context\n");

    // + cnmt.xml
    index += 1;

    // Set filesize for creating nsp
    nsp_ctx->nsp_entry[index].filesize = cnmt_xml_ctx->contents[index - 1].size;

    // Set filepath for creating nsp
    filepath_init(&nsp_ctx->nsp_entry[index].filepath);
    filepath_copy(&nsp_ctx->nsp_entry[index].filepath, filepath);

    // Set new filename for creating nsp
    if (content_type != 1)
    {
        nsp_ctx->nsp_entry[index].nsp_filename = (char *)calloc(1, 37);
        strncpy(nsp_ctx->nsp_entry[index].nsp_filename, cnmt_xml_ctx->contents[index - 1].id, 0x20);
        strcat(nsp_ctx->nsp_entry[index].nsp_filename, ".nca");
    }
    else // Meta nca
    {
        nsp_ctx->nsp_entry[index].nsp_filename = (char *)calloc(1, 42);
        strncpy(nsp_ctx->nsp_entry[index].nsp_filename, cnmt_xml_ctx->contents[index - 1].id, 0x20);
        strcat(nsp_ctx->nsp_entry[index].nsp_filename, ".cnmt.nca");
    }

    printf("DEBUG: nca_gamecard_process() - NSP entry configured\n");
    printf("DEBUG: nca_gamecard_process() - Function completed successfully for index %d\n", index - 1);
}

void nca_download_process(nca_ctx_t *ctx, filepath_t *filepath, int index, cnmt_xml_ctx_t *cnmt_xml_ctx, cnmt_ctx_t *cnmt_ctx, nsp_ctx_t *nsp_ctx)
{
    /* Decrypt header */
    if (!nca_decrypt_header(ctx))
    {
        fprintf(stderr, "Invalid NCA header! Are keys correct?\n");
        exit(EXIT_FAILURE);
    }

    uint8_t content_type = ctx->header.content_type;

    /* Sort out crypto type. */
    ctx->crypto_type = ctx->header.crypto_type;
    if (ctx->header.crypto_type2 > ctx->header.crypto_type)
        ctx->crypto_type = ctx->header.crypto_type2;
    if (ctx->crypto_type)
        ctx->crypto_type--; /* 0, 1 are both master key 0. */

    /* Rights ID. */
    for (unsigned int i = 0; i < 0x10; i++)
    {
        if (ctx->header.rights_id[i] != 0)
        {
            ctx->has_rights_id = 1;
            break;
        }
    }

    printf("Processing %s\n", filepath->char_path);

    // Set required values for creating .cnmt.xml
    cnmt_xml_ctx->contents[index].size = ctx->header.nca_size;
    if (ctx->has_rights_id)
    {
        cnmt_xml_ctx->contents[index].keygeneration = (unsigned char)ctx->header.rights_id[15];
        if (ctx->has_rights_id && ((nsp_ctx->nsp_entry[1].filepath.char_path[0] == 0) || (nsp_ctx->nsp_entry[2].filepath.char_path[0] == 0)))
        {
            // Convert rightsid to hex string
            char *rights_id = (char *)calloc(1, 33);
            hexBinaryString((unsigned char *)ctx->header.rights_id, 16, rights_id, 33);

            // Set tik file path for creating nsp
            filepath_init(&nsp_ctx->nsp_entry[1].filepath);
            filepath_copy(&nsp_ctx->nsp_entry[1].filepath, &ctx->tool_ctx->settings.secure_dir_path);
            filepath_append(&nsp_ctx->nsp_entry[1].filepath, "%s.tik", rights_id); // tik filename is: rightsid + .tik

            // Set cert file path for creating nsp
            filepath_init(&nsp_ctx->nsp_entry[2].filepath);
            filepath_copy(&nsp_ctx->nsp_entry[2].filepath, &ctx->tool_ctx->settings.secure_dir_path);
            filepath_append(&nsp_ctx->nsp_entry[2].filepath, "%s.cert", rights_id); // tik filename is: rightsid + .tik
            free(rights_id);

            // Set tik filename for creating nsp
            nsp_ctx->nsp_entry[1].nsp_filename = (char *)calloc(1, 37);
            strncpy(nsp_ctx->nsp_entry[1].nsp_filename, basename(nsp_ctx->nsp_entry[1].filepath.char_path), 36);

            // Set cert filename for creating nsp
            nsp_ctx->nsp_entry[2].nsp_filename = (char *)calloc(1, 38);
            strncpy(nsp_ctx->nsp_entry[2].nsp_filename, basename(nsp_ctx->nsp_entry[2].filepath.char_path), 37);

            // Set tik file size for creating nsp
            FILE *tik_file;
            if (!(tik_file = os_fopen(nsp_ctx->nsp_entry[1].filepath.os_path, OS_MODE_READ)))
            {
                fprintf(stderr, "unable to open %s: %s\n", nsp_ctx->nsp_entry[0].filepath.char_path, strerror(errno));
                exit(EXIT_FAILURE);
            }
            fseeko64(tik_file, 0, SEEK_END);
            nsp_ctx->nsp_entry[1].filesize = (uint64_t)ftello64(tik_file);
            fclose(tik_file);

            // Set cert file size for creating nsp
            FILE *cert_file;
            if (!(cert_file = os_fopen(nsp_ctx->nsp_entry[2].filepath.os_path, OS_MODE_READ)))
            {
                fprintf(stderr, "unable to open %s: %s\n", nsp_ctx->nsp_entry[1].filepath.char_path, strerror(errno));
                exit(EXIT_FAILURE);
            }
            fseeko64(cert_file, 0, SEEK_END);
            nsp_ctx->nsp_entry[2].filesize = (uint64_t)ftello64(cert_file);
            fclose(cert_file);

            cnmt_xml_ctx->keygen_min = (unsigned char)ctx->header.rights_id[15];
            cnmt_ctx->has_rightsid = 1;
        }
    }
    else
    {
        if (ctx->header.crypto_type2 > ctx->header.crypto_type)
            cnmt_xml_ctx->contents[index].keygeneration = ctx->header.crypto_type2;
        else
            cnmt_xml_ctx->contents[index].keygeneration = ctx->header.crypto_type;
    }

    // Process control nca
    if (content_type == 2 && ctx->tool_ctx->settings.titlename == 1)
        nca_control_nacp_process(ctx, nsp_ctx);

    char *hash_hex = (char *)calloc(1, 65);
    if (content_type != 1) // Meta nca lacks of content records
    {
        cnmt_xml_ctx->contents[index].type = cnmt_get_content_type(cnmt_ctx->cnmt_content_records[index].type);

        // Convert hash in meta to hex string
        hexBinaryString(cnmt_ctx->cnmt_content_records[index].hash, 32, hash_hex, 65);
    }
    else
    {
        cnmt_xml_ctx->contents[index].type = cnmt_get_content_type(0x00);

        // Calculate Meta hash
        sha_ctx_t *sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
        fseeko64(ctx->file, 0, SEEK_SET);
        unsigned char *buff = (unsigned char *)malloc(ctx->header.nca_size);
        unsigned char *meta_hash = (unsigned char *)malloc(0x20);
        if (fread(buff, 1, ctx->header.nca_size, ctx->file) != ctx->header.nca_size)
        {
            fprintf(stderr, "Failed to read Metadata!\n");
            exit(EXIT_FAILURE);
        }
        sha_update(sha_ctx, buff, ctx->header.nca_size);
        sha_get_hash(sha_ctx, meta_hash);
        free(buff);
        free_sha_ctx(sha_ctx);

        hexBinaryString(meta_hash, 32, hash_hex, 65);
    }
    fclose(ctx->file);

    // Set hash and id for xml meta, id = first 16 bytes of hash
    strncpy(cnmt_xml_ctx->contents[index].hash, hash_hex, 64);
    cnmt_xml_ctx->contents[index].hash[64] = '\0';
    strncpy(cnmt_xml_ctx->contents[index].id, hash_hex, 32);
    cnmt_xml_ctx->contents[index].id[32] = '\0';
    free(hash_hex);

    // 0: tik, 1: cert, 2: cnmt.xml
    index += 3;

    // Set filesize for creating nsp
    nsp_ctx->nsp_entry[index].filesize = cnmt_xml_ctx->contents[index - 3].size;

    // Set filepath for creating nsp
    filepath_init(&nsp_ctx->nsp_entry[index].filepath);
    filepath_copy(&nsp_ctx->nsp_entry[index].filepath, filepath);

    // Set new filename for creating nsp
    if (content_type != 1)
    {
        nsp_ctx->nsp_entry[index].nsp_filename = (char *)calloc(1, 37);
        strncpy(nsp_ctx->nsp_entry[index].nsp_filename, cnmt_xml_ctx->contents[index - 3].id, 0x20);
        strcat(nsp_ctx->nsp_entry[index].nsp_filename, ".nca");
    }
    else // Meta nca
    {
        nsp_ctx->nsp_entry[index].nsp_filename = (char *)calloc(1, 42);
        strncpy(nsp_ctx->nsp_entry[index].nsp_filename, cnmt_xml_ctx->contents[index - 3].id, 0x20);
        strcat(nsp_ctx->nsp_entry[index].nsp_filename, ".cnmt.nca");
    }
}

void nca_decrypt_key_area(nca_ctx_t *ctx)
{
    aes_ctx_t *aes_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.key_area_keys[ctx->crypto_type][ctx->header.kaek_ind], 16, AES_MODE_ECB);
    aes_decrypt(aes_ctx, ctx->decrypted_keys, ctx->header.encrypted_keys, 0x40);
    free_aes_ctx(aes_ctx);
}

/* Decrypt NCA header. */
int nca_decrypt_header(nca_ctx_t *ctx)
{
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&ctx->header, 1, 0xC00, ctx->file) != 0xC00)
    {
        fprintf(stderr, "Failed to read NCA header!\n");
        return 0;
    }
    ctx->is_decrypted = 0;

    nca_header_t dec_header;

    aes_ctx_t *hdr_aes_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.header_key, 32, AES_MODE_XTS);
    aes_xts_decrypt(hdr_aes_ctx, &dec_header, &ctx->header, 0x400, 0, 0x200);

    if (dec_header.magic == MAGIC_NCA3)
    {
        ctx->format_version = NCAVERSION_NCA3;
        aes_xts_decrypt(hdr_aes_ctx, &dec_header, &ctx->header, 0xC00, 0, 0x200);
        ctx->header = dec_header;
    }
    else
    {
        fprintf(stderr, "Invalid NCA magic!\n");
        exit(EXIT_FAILURE);
    }
    free_aes_ctx(hdr_aes_ctx);
    return ctx->format_version != NCAVERSION_UNKNOWN;
}

// Encrypt NCA header
void nca_encrypt_header(nca_ctx_t *ctx)
{
    nca_header_t enc_header;
    aes_ctx_t *hdr_aes_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.header_key, 32, AES_MODE_XTS);
    aes_xts_encrypt(hdr_aes_ctx, &enc_header, &ctx->header, 0xC00, 0, 0x200);
    ctx->header = enc_header;
    free_aes_ctx(hdr_aes_ctx);
}
