/*!
 * @file osi_types.h
 * @brief Base data types for PANDA OSI.
 */
#pragma once
#include <gmodule.h>
#include "panda/types.h"

/**
 * @brief Minimal handle for a process. Contains a unique identifier \p asid
 * and a task descriptor pointer \p taskd that can be used to retrieve the full
 * details of the process.
 */
typedef struct osi_proc_handle_struct {
    target_ptr_t taskd;
    target_ptr_t asid;
} OsiProcHandle;

/**
 * @brief Minimal information about a process thread.
 * Address space and open resources are shared between threads
 * of the same process. This information is stored in OsiProc.
 */
typedef struct osi_thread_struct {
    target_pid_t pid;
    target_pid_t tid;
} OsiThread;

/**
 * @brief Represents a page in the address space of a process.
 *
 * @note This has not been implemented/used so far.
 */
typedef struct osi_page_struct {
    target_ptr_t start;
    target_ulong len;
} OsiPage;

/**
 * @brief Represents information about a guest OS module (kernel module
 * or shared library).
 */
typedef struct osi_module_struct {
    target_ptr_t modd;
    target_ptr_t base;
    target_ptr_t size;
    char *file;
    char *name;
} OsiModule;

/**
 * @brief Detailed information for a process.
 */
typedef struct osi_proc_struct {
    target_ptr_t taskd;
    target_ptr_t asid;
    target_ptr_t pid;
    target_ptr_t ppid;
    char *name;
    OsiPage *pages;
    char *exe_path;
} OsiProc;


/* ******************************************************************
 * Helper functions for freeing/copying osi structs.
 ******************************************************************* */

/**
 * @brief Dummy function for freeing contents of OsiProcHandle.
 * Meant to be passed to g_array_set_clear_func().
 * Defining a NULL function pointer rather than an an empty function
 * avoids unneeded calls during g_array_free().
 */
static void UNUSED((*free_osiprochandle_contents)(OsiProcHandle *)) = NULL;

/**
 * @brief Frees an OsiProcHandle struct and its contents.
 * To be used for freeing standalone OsiProcHandle structs.
 */
static inline void free_osiprochandle(OsiProcHandle *h) {
    g_free(h);
}

/**
 * @brief Dummy function for freeing contents of OsiThread.
 * Meant to be passed to g_array_set_clear_func().
 * Defining a NULL function pointer rather than an an empty function
 * avoids unneeded calls during g_array_free().
 */
static void UNUSED((*free_osithread_contents)(OsiThread *)) = NULL;

/**
 * @brief Frees an OsiThread struct and its contents.
 * To be used for freeing standalone OsiThread structs.
 */
static inline void free_osithread(OsiThread *t) {
    g_free(t);
}

/**
 * @brief Dummy function for freeing contents of OsiPage.
 * Meant to be passed to g_array_set_clear_func().
 * Defining a NULL function pointer rather than an an empty function
 * avoids unneeded calls during g_array_free().
 */
static void UNUSED((*free_osipage_contents)(OsiPage *)) = NULL;

/**
 * @brief Frees an OsiPage struct and its contents.
 * To be used for freeing standalone OsiPage structs.
 */
static inline void free_osipage(OsiPage *p) {
    g_free(p);
}

/**
 * @brief Frees the contents of an OsiModule struct.
 * Meant to be passed to g_array_set_clear_func.
 */
static inline void free_osimodule_contents(OsiModule *m) {
    if (m == NULL) return;
    g_free(m->file);
    g_free(m->name);
}

/**
 * @brief Frees an OsiModule struct and its contents.
 * To be used for freeing standalone OsiModule structs.
 */
static inline void free_osimodule(OsiModule *m) {
    free_osimodule_contents(m);
    g_free(m);
}

/**
 * @brief Frees the contents of an OsiProc struct.
 * Meant to be passed to g_array_set_clear_func.
 */
static inline void free_osiproc_contents(OsiProc *p) {
    if (p == NULL) return;
    g_free(p->name);
    g_free(p->pages);
    g_free(p->exe_path);
}

/**
 * @brief Frees an OsiProc struct and its contents.
 * To be used for freeing standalone OsiProc structs.
 */
static inline void free_osiproc(OsiProc *p) {
    free_osiproc_contents(p);
    g_free(p);
}

/**
 * @brief Copies an OsiProc struct. Returns a pointer to the destination location.
 *
 * @note Members of `to` struct must have been freed to avoid memory leaks.
 */
static inline OsiProc *copy_osiproc(OsiProc *from, OsiProc *to) {
    if (from == NULL) return NULL;
    if (to == NULL) to = (OsiProc *)g_malloc0(sizeof(OsiProc));

    memcpy(to, from, sizeof(OsiProc));
    to->name = g_strdup(from->name);
    to->pages = NULL;  // OsiPage - TODO
    if (from->exe_path != NULL)
        to->exe_path = g_strdup(from->exe_path);
    else
        to->exe_path = NULL;
    return to;
}

static inline OsiModule *copy_osimod(OsiModule *from, OsiModule *to) {
    if (from == NULL) return NULL;
    if (to == NULL) to = (OsiModule *)g_malloc0(sizeof(OsiModule));

    memcpy(to, from, sizeof(OsiModule));
    to->name = g_strdup(from->name);
    to->file = g_strdup(from->file);
    return to;
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
