#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifndef _MSC_VER
#include <libgen.h>
#endif
#include "nsp.h"
#include "pfs0.h"
#include "utils.h"

void nsp_create(nsp_ctx_t *nsp_ctx)
{
    // nsp file name is tid.nsp
    printf("Creating nsp %s\n", nsp_ctx->filepath.char_path);
    printf("DEBUG: nsp_create() - Starting with %d entries\n", nsp_ctx->entry_count);

    uint32_t string_table_size = 42 * nsp_ctx->entry_count;
    pfs0_header_t nsp_header = {
        .magic = MAGIC_PFS0,
        .num_files = nsp_ctx->entry_count,
        .string_table_size = string_table_size,
        .reserved = 0};

    uint64_t offset = 0;
    uint32_t filename_offset = 0;
    char *string_table = (char *)calloc(1, string_table_size);
    nsp_file_entry_table_t *file_entry_table = (nsp_file_entry_table_t *)calloc(1, nsp_ctx->entry_count * sizeof(nsp_file_entry_table_t));

    // Fill file entry table and calculate total NSP size
    uint64_t total_nsp_size = sizeof(pfs0_header_t) + 
                              (nsp_ctx->entry_count * sizeof(nsp_file_entry_table_t)) + 
                              string_table_size;

    printf("DEBUG: Building file entry table...\n");
    for (int i = 0; i < nsp_ctx->entry_count; i++)
    {
        printf("DEBUG: Entry %d/%d - File: %s, Size: %llu bytes\n", 
               i + 1, nsp_ctx->entry_count,
               nsp_ctx->nsp_entry[i].nsp_filename,
               (unsigned long long)nsp_ctx->nsp_entry[i].filesize);

        file_entry_table[i].offset = offset;
        file_entry_table[i].filename_offset = filename_offset;
        file_entry_table[i].padding = 0;
        file_entry_table[i].size = nsp_ctx->nsp_entry[i].filesize;
        offset += nsp_ctx->nsp_entry[i].filesize;
        total_nsp_size += nsp_ctx->nsp_entry[i].filesize;
        strcpy(string_table + filename_offset, nsp_ctx->nsp_entry[i].nsp_filename);
        filename_offset += strlen(nsp_ctx->nsp_entry[i].nsp_filename) + 1;
    }

    printf("Total NSP size: %.2f MB (%d files)\n", 
           total_nsp_size / (1024.0 * 1024.0), nsp_ctx->entry_count);
    printf("DEBUG: Opening NSP file for writing...\n");

    FILE *nsp_file;
    if ((nsp_file = os_fopen(nsp_ctx->filepath.os_path, OS_MODE_WRITE)) == NULL)
    {
        fprintf(stderr, "unable to create nsp\n");
        exit(EXIT_FAILURE);
    }
    printf("DEBUG: NSP file opened successfully\n");

    /* Set large buffer for NSP output file to improve write performance */
    unsigned char *nsp_file_buffer = malloc(16 * 1024 * 1024); /* 16MB file buffer */
    if (nsp_file_buffer != NULL) {
        setvbuf(nsp_file, (char*)nsp_file_buffer, _IOFBF, 16 * 1024 * 1024);
        printf("DEBUG: Set 16MB output buffer\n");
    }

    // Write header
    printf("DEBUG: Writing NSP header...\n");
    if (!fwrite(&nsp_header, sizeof(pfs0_header_t), 1, nsp_file))
    {
        fprintf(stderr, "Unable to write nsp header");
        if (nsp_file_buffer) free(nsp_file_buffer);
        fclose(nsp_file);
        exit(EXIT_FAILURE);
    }

    // Write file entry table
    printf("DEBUG: Writing file entry table...\n");
    if (!fwrite(file_entry_table, sizeof(nsp_file_entry_table_t), nsp_ctx->entry_count, nsp_file))
    {
        fprintf(stderr, "Unable to write nsp file entry table");
        if (nsp_file_buffer) free(nsp_file_buffer);
        fclose(nsp_file);
        exit(EXIT_FAILURE);
    }

    // Write string table
    printf("DEBUG: Writing string table...\n");
    if (!fwrite(string_table, 1, string_table_size, nsp_file))
    {
        fprintf(stderr, "Unable to write nsp string table");
        if (nsp_file_buffer) free(nsp_file_buffer);
        fclose(nsp_file);
        exit(EXIT_FAILURE);
    }

    // **OPTIMIZATION: Allocate reusable buffer ONCE for all files**
    uint64_t buffer_size = 512 * 1024 * 1024; // 512 MB buffer
    printf("DEBUG: Allocating 512MB reusable buffer...\n");
    unsigned char *reusable_buf = malloc(buffer_size);
    if (reusable_buf == NULL)
    {
        fprintf(stderr, "Failed to allocate I/O buffer!\n");
        if (nsp_file_buffer) free(nsp_file_buffer);
        fclose(nsp_file);
        exit(EXIT_FAILURE);
    }
    printf("DEBUG: Buffer allocated successfully\n");

    // Pack all files into NSP
    uint64_t bytes_written = sizeof(pfs0_header_t) + 
                             (nsp_ctx->entry_count * sizeof(nsp_file_entry_table_t)) + 
                             string_table_size;

    printf("DEBUG: Starting to pack %d files...\n", nsp_ctx->entry_count);
    for (int i2 = 0; i2 < nsp_ctx->entry_count; i2++)
    {
        FILE *nsp_data_file;
        printf("\n[%d/%d] Packing %s (%.2f MB)\n", 
               i2 + 1, nsp_ctx->entry_count,
               nsp_ctx->nsp_entry[i2].nsp_filename,
               nsp_ctx->nsp_entry[i2].filesize / (1024.0 * 1024.0));
        printf("DEBUG: Opening input file: %s\n", nsp_ctx->nsp_entry[i2].filepath.char_path);

        if (!(nsp_data_file = os_fopen(nsp_ctx->nsp_entry[i2].filepath.os_path, OS_MODE_READ)))
        {
            fprintf(stderr, "unable to open %s: %s\n", nsp_ctx->nsp_entry[i2].filepath.char_path, strerror(errno));
            free(reusable_buf);
            if (nsp_file_buffer) free(nsp_file_buffer);
            fclose(nsp_file);
            exit(EXIT_FAILURE);
        }
        printf("DEBUG: Input file opened successfully\n");

        /* Set large buffer for input file to improve read performance */
        unsigned char *input_file_buffer = malloc(16 * 1024 * 1024); /* 16MB buffer */
        if (input_file_buffer != NULL) {
            setvbuf(nsp_data_file, (char*)input_file_buffer, _IOFBF, 16 * 1024 * 1024);
            printf("DEBUG: Set 16MB input buffer\n");
        }

        // **OPTIMIZATION: Adaptive chunk size based on file size**
        uint64_t file_size = nsp_ctx->nsp_entry[i2].filesize;
        uint64_t chunk_size = buffer_size;

        // For small files (< 100MB), use smaller chunks to reduce overhead
        if (file_size < 100 * 1024 * 1024) {
            chunk_size = (file_size < 10 * 1024 * 1024) ? 10 * 1024 * 1024 : 50 * 1024 * 1024;
        }

        printf("DEBUG: File size: %llu bytes, Chunk size: %llu bytes\n", 
               (unsigned long long)file_size, (unsigned long long)chunk_size);

        uint64_t ofs = 0;
        uint64_t last_progress = 0;
        int loop_iteration = 0;

        printf("DEBUG: Starting read/write loop...\n");
        while (ofs < file_size)
        {
            loop_iteration++;
            if (loop_iteration % 100 == 0) {
                printf("DEBUG: Loop iteration %d, offset: %llu / %llu\n", 
                       loop_iteration, (unsigned long long)ofs, (unsigned long long)file_size);
            }

            uint64_t read_size = chunk_size;
            if (ofs + read_size >= file_size)
                read_size = file_size - ofs;

            printf("DEBUG: [Iter %d] Reading %llu bytes at offset %llu\n",
                   loop_iteration, (unsigned long long)read_size, (unsigned long long)ofs);

            size_t bytes_read = fread(reusable_buf, 1, read_size, nsp_data_file);
            if (bytes_read != read_size)
            {
                fprintf(stderr, "ERROR: Failed to read file %s - Expected %llu bytes, got %zu bytes\n", 
                        nsp_ctx->nsp_entry[i2].filepath.char_path,
                        (unsigned long long)read_size, bytes_read);
                fprintf(stderr, "DEBUG: Current offset: %llu, File size: %llu, EOF: %d, Error: %d\n",
                        (unsigned long long)ofs, (unsigned long long)file_size,
                        feof(nsp_data_file), ferror(nsp_data_file));
                free(reusable_buf);
                if (input_file_buffer) free(input_file_buffer);
                fclose(nsp_data_file);
                if (nsp_file_buffer) free(nsp_file_buffer);
                fclose(nsp_file);
                exit(EXIT_FAILURE);
            }
            printf("DEBUG: [Iter %d] Read %zu bytes successfully\n", loop_iteration, bytes_read);

            printf("DEBUG: [Iter %d] Writing %llu bytes to NSP\n", 
                   loop_iteration, (unsigned long long)read_size);
            size_t bytes_written_chunk = fwrite(reusable_buf, 1, read_size, nsp_file);
            if (bytes_written_chunk != read_size)
            {
                fprintf(stderr, "ERROR: Failed to write to NSP file - Expected %llu bytes, wrote %zu bytes\n",
                        (unsigned long long)read_size, bytes_written_chunk);
                free(reusable_buf);
                if (input_file_buffer) free(input_file_buffer);
                fclose(nsp_data_file);
                if (nsp_file_buffer) free(nsp_file_buffer);
                fclose(nsp_file);
                exit(EXIT_FAILURE);
            }
            printf("DEBUG: [Iter %d] Wrote %zu bytes successfully\n", loop_iteration, bytes_written_chunk);

            ofs += read_size;
            bytes_written += read_size;

            printf("DEBUG: [Iter %d] Updated offset to %llu (%.1f%% complete)\n",
                   loop_iteration, (unsigned long long)ofs, 
                   (ofs * 100.0) / file_size);

            // **OPTIMIZATION: Progress indication for large files (> 100MB)**
            if (file_size > 100 * 1024 * 1024) {
                uint64_t progress = (ofs * 100) / file_size;
                if (progress >= last_progress + 10) { // Show every 10%
                    printf("  Progress: %llu%%\n", (unsigned long long)progress);
                    fflush(stdout);
                    last_progress = progress;
                }
            }

            // Safety check for infinite loop
            if (loop_iteration > 10000) {
                fprintf(stderr, "ERROR: Possible infinite loop detected! Loop iteration: %d\n", loop_iteration);
                fprintf(stderr, "DEBUG: offset=%llu, file_size=%llu, chunk_size=%llu\n",
                        (unsigned long long)ofs, (unsigned long long)file_size, (unsigned long long)chunk_size);
                free(reusable_buf);
                if (input_file_buffer) free(input_file_buffer);
                fclose(nsp_data_file);
                if (nsp_file_buffer) free(nsp_file_buffer);
                fclose(nsp_file);
                exit(EXIT_FAILURE);
            }
        }

        printf("DEBUG: Loop completed after %d iterations\n", loop_iteration);

        if (file_size > 100 * 1024 * 1024) {
            printf("  Progress: 100%% - Complete!\n");
        }

        printf("DEBUG: Closing input file...\n");
        fclose(nsp_data_file);
        if (input_file_buffer) free(input_file_buffer);
        printf("DEBUG: File %d/%d packed successfully\n", i2 + 1, nsp_ctx->entry_count);
    }

    // Free the reusable buffer once at the end
    printf("DEBUG: Freeing reusable buffer...\n");
    free(reusable_buf);

    printf("DEBUG: Closing NSP file...\n");
    fclose(nsp_file);
    if (nsp_file_buffer) free(nsp_file_buffer);

    printf("\nNSP created successfully: %.2f MB total\n", bytes_written / (1024.0 * 1024.0));
    printf("DEBUG: nsp_create() - Completed successfully\n");
    printf("\n");
}
