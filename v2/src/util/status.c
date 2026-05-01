/* SPDX-License-Identifier: ISC */
#include <stratum/types.h>

const char *stm_strerror(stm_status s)
{
    switch (s) {
    case STM_OK:             return "ok";
    case STM_EINVAL:         return "invalid argument";
    case STM_ENOMEM:         return "out of memory";
    case STM_ENOSPC:         return "no space";
    case STM_EOVERFLOW:      return "overflow";
    case STM_ERANGE:         return "out of range";
    case STM_EIO:            return "i/o error";
    case STM_ENOENT:         return "no such entry";
    case STM_EEXIST:         return "entry exists";
    case STM_EACCES:         return "access denied";
    case STM_EBUSY:          return "busy";
    case STM_EAGAIN:         return "try again";
    case STM_ENODEV:         return "no device";
    case STM_EROFS:          return "read-only filesystem";
    case STM_EXDEV:          return "cross-device link refused";
    case STM_ECORRUPT:       return "integrity check failed";
    case STM_EBADTAG:        return "aead tag mismatch";
    case STM_EBADVERSION:    return "unsupported format version";
    case STM_EBADFEATURE:    return "required feature flag unknown";
    case STM_EWEDGED:        return "filesystem wedged";
    case STM_ENOTSUPPORTED:  return "not supported";
    case STM_EPROTOCOL:      return "protocol violation";
    case STM_EBACKEND:       return "backend error";
    case STM_EQUORUM:        return "quorum not reached";
    case STM_ENOTDIR:        return "not a directory";
    case STM_EISDIR:         return "is a directory";
    case STM_ENOTEMPTY:      return "directory not empty";
    case STM_ENAMETOOLONG:   return "name or target too long";
    case STM_ENODATA:        return "no such xattr";
    }
    return "unknown error";
}
