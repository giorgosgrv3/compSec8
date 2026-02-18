#define _XOPEN_SOURCE
#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <linux/limits.h>
#include <getopt.h>

#define MALICIOUS_THRESHOLD 5  // > 5 distinct files with denied access

// Helper struct to track files opened by processes
struct open_file_entry {
    int pid;
    char *filepath;
    struct open_file_entry *next;
};

// Helper: resolve filenames  
static int filename_matches(const char *logged, const char *query)
{
    if (strcmp(logged, query) == 0) return 1;
    const char *base = strrchr(logged, '/');
    if (base) {
        base++;
        if (strcmp(base, query) == 0) return 1;
    }
    return 0;
}

void usage(void)
{
    printf(
           "\n"
           "usage:\n"
           "\t./audit_monitor [options]\n"
           "Options:\n"
           "-s             Print malicious users (access denials)\n"
           "-i <filename>  Print modification history for <filename>\n"
           "-v <limit>     Detect mass file creation (burst > limit in 20m)\n"
           "-e             Detect ransomware encryption patterns (.enc)\n"
           "-h             Help message\n\n"
           );
    exit(1);
}

//High-volume file creation 
//Checks if > X files were created (Op 0) in the last 20 minutes.

void detect_mass_creation(FILE *log, int x_threshold) {
    rewind(log);
    char line[1024];
    int creation_count = 0;
    
    // Get current UTC time
    time_t now_local = time(NULL);
    struct tm *utc_now_tm = gmtime(&now_local);
    time_t now_utc = timegm(utc_now_tm); 
    
    // 20 minute window
    time_t cutoff = now_utc - (20 * 60); 

    printf("\n--- Scanning for Mass File Creation (Last 20m UTC) ---\n");

    while (fgets(line, sizeof(line), log)) {
        int uid, pid, op, denied;
        char path[PATH_MAX], date_str[11], time_str[9], hash[65];

        // Parse log line
        if (sscanf(line, "%d %d %s %s %s %d %d %s", 
                   &uid, &pid, path, date_str, time_str, &op, &denied, hash) == 8) {
            
            // CHECK: Operation 0 is CREATE 
            // CHECK: Denied 0 means success
            if (op == 0 && denied == 0) { 
                struct tm tm_info = {0};
                char full_dt[25];
                snprintf(full_dt, sizeof(full_dt), "%s %s", date_str, time_str);
                
                if (strptime(full_dt, "%Y-%m-%d %H:%M:%S", &tm_info) != NULL) {
                    time_t event_time = timegm(&tm_info); 
                    
                    if (event_time >= cutoff) {
                        creation_count++;
                    }
                }
            }
        }
    }

    if (creation_count >= x_threshold) {
        printf("[ALERT] POTENTIAL RANSOMWARE: %d files created in last 20m (Threshold: %d)\n", 
                creation_count, x_threshold);
    } else {
        printf("Activity Normal: %d creations in 20m window.\n", creation_count);
    }
}

// Requirement 3.4.2: Encryption-and-delete workflow detection
// Detects: Open "file" (Op 1) -> Create "file.enc" (Op 0) by same PID
 
void detect_ransomware_patterns(FILE *log) {
    rewind(log);
    char line[1024];
    
    // Linked list to store history of OPEN events: (PID, filename)
    struct open_file_entry *history_head = NULL;

    printf("\n--- Scanning for Ransomware Encryption Patterns (.enc) ---\n");
    int anomalies_found = 0;

    while (fgets(line, sizeof(line), log)) {
        int uid, pid, op, denied;
        char path[PATH_MAX], date_str[11], time_str[9], hash[65];

        if (sscanf(line, "%d %d %s %s %s %d %d %s", 
                   &uid, &pid, path, date_str, time_str, &op, &denied, hash) == 8) {

            // File OPEN event (Op 1) - Store in history
            if (op == 1 && denied == 0) {
                struct open_file_entry *new_node = malloc(sizeof(struct open_file_entry));
                if (new_node) {
                    new_node->pid = pid;
                    new_node->filepath = strdup(path);
                    new_node->next = history_head;
                    history_head = new_node;
                }
            }

            //File CREATE event (Op 0) - Check for suspicious suffix
            else if (op == 0 && denied == 0) {
                size_t path_len = strlen(path);
                
                // Check if created file ends in ".enc"
                if (path_len > 4 && strcmp(path + path_len - 4, ".enc") == 0) {
                    
                    // Construct the expected original filename (remove .enc)
                    char original_file[PATH_MAX];
                    strncpy(original_file, path, path_len - 4);
                    original_file[path_len - 4] = '\0';

                    // Scan history
                    struct open_file_entry *curr = history_head;
                    while (curr != NULL) {
                        if (curr->pid == pid && strcmp(curr->filepath, original_file) == 0) {
                            printf("[ALERT] RANSOMWARE PATTERN: PID %d opened '%s' then created '%s'\n",
                                   pid, original_file, path);
                            anomalies_found = 1;
                            break; // specific match found
                        }
                        curr = curr->next;
                    }
                }
            }
        }
    }

    if (!anomalies_found) {
        printf("No encryption patterns detected.\n");
    }

    // Cleanup
    while (history_head) {
        struct open_file_entry *temp = history_head;
        history_head = history_head->next;
        free(temp->filepath);
        free(temp);
    }
}

void list_unauthorized_accesses(FILE *log)
{
    rewind(log);

    struct user_info {
        int uid;
        int num_files;
        int cap;
        char **files;
    };
    struct user_info *users = NULL;
    int users_count = 0, users_cap = 0;

    int uid, operation, action_denied;
    pid_t pid;
    char filename[PATH_MAX], date[11], time_buf[9], hash[65];

    while (fscanf(log, "%d %d %s %10s %8s %d %d %64s",
                  &uid, &pid, filename, date, time_buf,
                  &operation, &action_denied, hash) == 8) {

        if (action_denied == 0) continue;

        // Find or create user
        int uidx = -1;
        for (int i = 0; i < users_count; i++) {
            if (users[i].uid == uid) { uidx = i; break; }
        }

        if (uidx == -1) {
            // Expand users array if needed
            if (users_count == users_cap) {
                int new_cap = (users_cap == 0) ? 4 : users_cap * 2;
                users = realloc(users, new_cap * sizeof(*users));
                users_cap = new_cap;
            }
            users[users_count].uid = uid;
            users[users_count].num_files = 0;
            users[users_count].cap = 0;
            users[users_count].files = NULL;
            uidx = users_count++;
        }

        struct user_info *u = &users[uidx];
        int already_counted = 0;
        for(int j=0; j<u->num_files; j++) {
            if(strcmp(u->files[j], filename) == 0) { already_counted = 1; break; }
        }

        if(!already_counted) {
            if(u->num_files == u->cap) {
                int new_cap = (u->cap == 0) ? 4 : u->cap * 2;
                u->files = realloc(u->files, new_cap * sizeof(char*));
                u->cap = new_cap;
            }
            u->files[u->num_files++] = strdup(filename);
        }
    }

    printf(" ---- (malicious) users with more than %d distinct denied files: --- \n",
           MALICIOUS_THRESHOLD);
    int found = 0;
    for (int i = 0; i < users_count; i++) {
        if (users[i].num_files > MALICIOUS_THRESHOLD) {
            printf("%d\n", users[i].uid);
            found = 1;
        }
        // Cleanup inner
        for(int j=0; j<users[i].num_files; j++) free(users[i].files[j]);
        free(users[i].files);
    }
    if (!found) printf("no malicious users found.\n");
    free(users);
}


void list_file_modifications(FILE *log, char *file_to_scan)
{
    rewind(log);

    struct user_mod { int uid; int mods; };
    struct user_mod *users = NULL;
    int users_count = 0, users_cap = 0;
    char **unique_hashes = NULL;
    int unique_count = 0, unique_cap = 0;
    char last_hash[65];
    int have_last_hash = 0;

    int uid, op, denied;
    pid_t pid;
    char path[PATH_MAX], d[11], t[9], h[65];

    while (fscanf(log, "%d %d %s %10s %8s %d %d %64s",
                  &uid, &pid, path, d, t, &op, &denied, h) == 8) {
        
        if (!filename_matches(path, file_to_scan)) continue;
        if (denied != 0) continue;
        if (op != 3 && op != 0) continue; // Close or Create

        // Track unique hashes
        int seen = 0;
        for(int i=0; i<unique_count; i++) {
            if(strcmp(unique_hashes[i], h) == 0) { seen = 1; break; }
        }
        if(!seen) {
             if(unique_count == unique_cap) {
                int nc = (unique_cap==0)?4:unique_cap*2;
                unique_hashes = realloc(unique_hashes, nc*sizeof(char*));
                unique_cap = nc;
             }
             unique_hashes[unique_count++] = strdup(h);
             if(op == 3) unique_count++; 
        }

        // Detect mods
        int is_mod = 0;
        if (!have_last_hash) {
            strcpy(last_hash, h);
            have_last_hash = 1;
        } else {
            if(strcmp(last_hash, h) != 0) {
                is_mod = 1;
                strcpy(last_hash, h);
            }
        }

        if(!is_mod) continue;

        int uidx = -1;
        for(int i=0; i<users_count; i++) {
            if(users[i].uid == uid) { uidx = i; break; }
        }
        if(uidx == -1) {
            if(users_count == users_cap) {
                int nc = (users_cap==0)?4:users_cap*2;
                users = realloc(users, nc*sizeof(*users));
                users_cap = nc;
            }
            users[users_count].uid = uid;
            users[users_count].mods = 0;
            uidx = users_count++;
        }
        users[uidx].mods++;
    }

    printf("File: %s\n", file_to_scan);
    printf("User modifications:\n");
    for(int i=0; i<users_count; i++) printf("  UID %d -> %d\n", users[i].uid, users[i].mods);
    printf("Unique states: %d\n", unique_count);

    // Cleanup
    for(int i=0; i<unique_count; i++) free(unique_hashes[i]);
    free(unique_hashes);
    free(users);
}

int main(int argc, char *argv[])
{
    int ch;
    FILE *log;

    if (argc < 2) usage();

    log = fopen("./access_audit.log", "r");
    if (log == NULL) {
        printf("Error opening log file \"./access_audit.log\"\n");
        return 1;
    }

    while ((ch = getopt(argc, argv, "hi:sv:e")) != -1) {
        switch (ch) {       
        case 'i':
            list_file_modifications(log, optarg);
            break;
        case 's':
            list_unauthorized_accesses(log);
            break;
        case 'v': 
            detect_mass_creation(log, atoi(optarg));
            break;
        case 'e':
            detect_ransomware_patterns(log);
            break;
        default:
            usage();
        }
    }

    fclose(log);
    return 0;
}