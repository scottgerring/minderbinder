//go:build ignore
#pragma once

#define TASK_COMM_LENGTH 1024

/**
 * Helper function to compare two strings
 */
static __inline int compare_comm(const char *comm1, const char *comm2) {
    for (int i = 0; i < TASK_COMM_LENGTH; i++) {
        if (comm1[i] != comm2[i]) {
            return 0;
        }
        if (comm1[i] == 0 && comm2[i] == 0) {
            return 1;
        }
    }
    return 1; // Strings are equal if loop completes
}