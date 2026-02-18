#define _GNU_SOURCE

#include <limits.h>
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h> 
#include <stdarg.h> 
#include <fcntl.h>  

#define LOG_FILE_PATH "access_audit.log"
#define HASH_SIZE 64 

// --- 1. GLOBAL POINTERS ---
static FILE *(*real_fopen)(const char*, const char*) = NULL;
static FILE *(*real_fopen64)(const char*, const char*) = NULL; // NEW
static size_t (*real_fwrite)(const void*, size_t, size_t, FILE*) = NULL;
static int (*real_fclose)(FILE*) = NULL;


static int (*real_open)(const char *pathname, int flags, ...) = NULL;


static __thread int in_logger = 0; 

// --- 2. LOAD FUNCTIONS ---
void load_real_functions() {
    if (!real_fopen)   real_fopen   = dlsym(RTLD_NEXT, "fopen");
    if (!real_fopen64) real_fopen64 = dlsym(RTLD_NEXT, "fopen64"); // NEW
    if (!real_fwrite)  real_fwrite  = dlsym(RTLD_NEXT, "fwrite");
    if (!real_fclose)  real_fclose  = dlsym(RTLD_NEXT, "fclose");
    if (!real_open)    real_open    = dlsym(RTLD_NEXT, "open");
}

// --- 3. HELPER FUNCTIONS ---
const char *get_path_from_stream(FILE *stream) {
    if (stream == NULL) return NULL;
    int fd = fileno(stream);
    if (fd == -1) return NULL;

    static char path_buf[PATH_MAX];
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(link_path, path_buf, sizeof(path_buf) - 1);
    if (len == -1) return NULL;

    path_buf[len] = '\0';
    return path_buf;
}

void log_event(const char *path, int operation, int action_denied, const char *file_hash) {
    load_real_functions(); 
    
    time_t now;
    struct tm *tm_struct;
    char date_buf[11];
    char time_buf[9];
    
    time(&now);
    tm_struct = gmtime(&now);
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", tm_struct);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_struct);

    FILE *log_file = real_fopen(LOG_FILE_PATH, "a");
    if (log_file == NULL) return;

    fprintf(log_file, "%d %d %s %s %s %d %d %s\n",
            getuid(), getpid(), path, date_buf, time_buf,
            operation, action_denied, file_hash
    );

    real_fclose(log_file);
}

char *sha256_file_hash(const char *path) {
    static char hex_hash[HASH_SIZE + 1];
    load_real_functions(); 

    memset(hex_hash, '0', HASH_SIZE);
    hex_hash[HASH_SIZE] = '\0';

    struct stat st;
    // Check if regular file to avoid hanging on /dev/urandom
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return hex_hash; 
    }

    FILE *file = real_fopen(path, "r");
    if (file == NULL) return hex_hash;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        real_fclose(file);
        return hex_hash;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        real_fclose(file);
        return hex_hash;
    }

    char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(mdctx);
            real_fclose(file);
            return hex_hash;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        real_fclose(file);
        return hex_hash;
    }

    EVP_MD_CTX_free(mdctx);
    real_fclose(file);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&hex_hash[i * 2], "%02x", hash[i]);
    }
    return hex_hash;
}

// --- 4. INTERCEPTED FUNCTIONS ---

// Intercept fopen64 (Used by openssl for streams)
FILE *fopen64(const char *path, const char *mode) {
    load_real_functions();
    if (in_logger) return real_fopen64(path, mode);

    in_logger = 1;

    struct stat st;
    int existed_before = (stat(path, &st) == 0);

    FILE *ret = real_fopen64(path, mode);

    int operation;
    int action_denied = 0;

    if (ret == NULL) {
        action_denied = 1;
        operation = existed_before ? 1 : 0; 
    } else {
        operation = existed_before ? 1 : 0;
    }
    
    char *hash = sha256_file_hash(path); 
    log_event(path, operation, action_denied, hash);

    in_logger = 0;
    return ret;
}

FILE *fopen(const char *path, const char *mode) {
    load_real_functions();
    if (in_logger) return real_fopen(path, mode);

    in_logger = 1;

    struct stat st;
    int existed_before = (stat(path, &st) == 0);

    FILE *ret = real_fopen(path, mode);

    int operation;
    int action_denied = 0;

    if (ret == NULL) {
        action_denied = 1;
        operation = existed_before ? 1 : 0; 
    } else {
        operation = existed_before ? 1 : 0;
    }
    
    char *hash = sha256_file_hash(path); 
    log_event(path, operation, action_denied, hash);

    in_logger = 0;
    return ret;
}

// Low-level open hooks 
void handle_open_log(const char *pathname, int fd, int existed_before) {
    if (in_logger) return;
    in_logger = 1;

    int operation;
    int action_denied = 0;

    if (fd == -1) {
        action_denied = 1;
        operation = existed_before ? 1 : 0; 
    } else {
        operation = existed_before ? 1 : 0;
    }

    char *hash = sha256_file_hash(pathname);
    log_event(pathname, operation, action_denied, hash);
    in_logger = 0;
}

int open(const char *pathname, int flags, ...) {
    load_real_functions();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (in_logger) return (flags & O_CREAT) ? real_open(pathname, flags, mode) : real_open(pathname, flags);
    
    struct stat st;
    int existed_before = (stat(pathname, &st) == 0);
    int fd = (flags & O_CREAT) ? real_open(pathname, flags, mode) : real_open(pathname, flags);
    handle_open_log(pathname, fd, existed_before);
    return fd;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    load_real_functions();
    if (in_logger) return real_fwrite(ptr, size, nmemb, stream);
    
    in_logger = 1;
    size_t ret = real_fwrite(ptr, size, nmemb, stream);
    

    const char *path = get_path_from_stream(stream);
    int denied = (ret != nmemb);
    
    if (path) {
        log_event(path, 2, denied, "WRITE_IN_PROGRESS_NO_HASH");
    } else {
        char zeros[65];
        memset(zeros, '0', 64);
        zeros[64] = '\0';
        log_event("UNKNOWN", 2, denied, zeros);
    }
    in_logger = 0;
    return ret;
}

int fclose(FILE *stream) {
    load_real_functions();
    if (in_logger) return real_fclose(stream);
    
    in_logger = 1;
    const char *path = get_path_from_stream(stream);
    char path_copy[PATH_MAX];
    
    if (path) strcpy(path_copy, path);
    else strcpy(path_copy, "UNKNOWN");

    int ret = real_fclose(stream);

    char *hash;
    if (strcmp(path_copy, "UNKNOWN") != 0) {
        hash = sha256_file_hash(path_copy);
    } else {
        hash = calloc(65, sizeof(char));
        memset(hash, '0', 64);
    }

    log_event(path_copy, 3, (ret != 0), hash);
    if (strcmp(path_copy, "UNKNOWN") == 0) free(hash);

    in_logger = 0;
    return ret;
}