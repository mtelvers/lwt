/* This file is part of Lwt, released under the MIT license. See LICENSE.md for
   details, or visit https://github.com/ocsigen/lwt/blob/master/LICENSE.md. */

#include "lwt_config.h"

#if defined(LWT_ON_WINDOWS)

#if OCAML_VERSION < 41300
#define CAML_INTERNALS
#endif
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/unixsupport.h>
#include <caml/osdeps.h>
#include "lwt_unix.h"

/* Map OCaml Unix.open_flag to Windows CreateFile parameters.
   Order must match the Unix.open_flag variant definition in OCaml 4.14:
   O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_NONBLOCK=3, O_APPEND=4,
   O_CREAT=5, O_TRUNC=6, O_EXCL=7, O_NOCTTY=8, O_DSYNC=9,
   O_SYNC=10, O_RSYNC=11, O_SHARE_DELETE=12, O_CLOEXEC=13, O_KEEPEXEC=14 */

/* Open a file with FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
   to avoid "Permission denied" errors when renaming/deleting parent dirs
   while files are still open. Uses CreateFileW directly rather than
   _wsopen_s (which only supports FILE_SHARE_READ|FILE_SHARE_WRITE via
   _SH_DENYNO, missing the critical FILE_SHARE_DELETE flag).
   Returns a Unix.file_descr (wrapping a HANDLE). */
CAMLprim value lwt_unix_win32_open(value path, value vflags, value vperm)
{
    CAMLparam3(path, vflags, vperm);
    HANDLE handle;
    char_os *wpath;
    DWORD dwDesiredAccess = 0;
    DWORD dwCreationDisposition = OPEN_EXISTING;
    DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    SECURITY_ATTRIBUTES sa;
    int has_creat = 0, has_trunc = 0, has_excl = 0, has_keepexec = 0;
    value flags;

    /* Walk the OCaml flag list to determine access mode and creation flags */
    for (flags = vflags; flags != Val_emptylist; flags = Field(flags, 1)) {
        int flag = Int_val(Field(flags, 0));
        switch (flag) {
        case 0: /* O_RDONLY */
            dwDesiredAccess |= GENERIC_READ;
            break;
        case 1: /* O_WRONLY */
            dwDesiredAccess |= GENERIC_WRITE;
            break;
        case 2: /* O_RDWR */
            dwDesiredAccess |= GENERIC_READ | GENERIC_WRITE;
            break;
        case 3: /* O_NONBLOCK - not meaningful for files on Windows */
            break;
        case 4: /* O_APPEND */
            dwDesiredAccess |= FILE_APPEND_DATA;
            break;
        case 5: /* O_CREAT */
            has_creat = 1;
            break;
        case 6: /* O_TRUNC */
            has_trunc = 1;
            break;
        case 7: /* O_EXCL */
            has_excl = 1;
            break;
        case 8:  /* O_NOCTTY */
        case 9:  /* O_DSYNC */
        case 10: /* O_SYNC */
        case 11: /* O_RSYNC */
            break;
        case 12: /* O_SHARE_DELETE - already in dwShareMode */
            break;
        case 13: /* O_CLOEXEC */
            break;
        case 14: /* O_KEEPEXEC */
            has_keepexec = 1;
            break;
        }
    }

    /* If no access mode was specified, default to read */
    if (dwDesiredAccess == 0)
        dwDesiredAccess = GENERIC_READ;

    /* Determine creation disposition from O_CREAT, O_TRUNC, O_EXCL */
    if (has_creat && has_excl)
        dwCreationDisposition = CREATE_NEW;
    else if (has_creat && has_trunc)
        dwCreationDisposition = CREATE_ALWAYS;
    else if (has_creat)
        dwCreationDisposition = OPEN_ALWAYS;
    else if (has_trunc)
        dwCreationDisposition = TRUNCATE_EXISTING;
    else
        dwCreationDisposition = OPEN_EXISTING;

    /* Non-inheritable by default; O_KEEPEXEC makes the handle inheritable */
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = has_keepexec ? TRUE : FALSE;

    wpath = caml_stat_strdup_to_os(String_val(path));

    handle = CreateFileW(
        wpath,
        dwDesiredAccess,
        dwShareMode,
        &sa,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        NULL
    );

    caml_stat_free(wpath);

    if (handle == INVALID_HANDLE_VALUE) {
        win32_maperr(GetLastError());
        uerror("open", path);
    }

    CAMLreturn(win_alloc_handle(handle));
}

#endif
