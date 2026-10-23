#include "PrivateACL.h"
#include <errno.h>
#if defined(__APPLE__)
#include <sys/acl.h>

int av_check_acl(int descriptor, int ancestor) {
    acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    // Darwin reports ENOENT when this descriptor has no extended ACL.
    if (!acl) return errno == ENOENT ? 0 : -1;
    int result = -1;
    if (acl_valid(acl) != 0) goto done;
    acl_entry_t entry;
    int index = ACL_FIRST_ENTRY;
    for (;;) {
        errno = 0;
        if (acl_get_entry(acl, index, &entry) != 0) {
            // Darwin returns -1/EINVAL at the end (unlike POSIX/Linux's 0).
            result = errno == EINVAL ? 0 : -1;
            break;
        }
        index = ACL_NEXT_ENTRY;
        if (!ancestor) { result = 1; break; }
        acl_tag_t tag;
        if (acl_get_tag_type(entry, &tag) != 0) break;
        if (tag == ACL_EXTENDED_DENY) continue; // e.g. macOS's ordinary deny-delete
        if (tag != ACL_EXTENDED_ALLOW) break;
        acl_permset_mask_t permissions;
        if (acl_get_permset_mask_np(entry, &permissions) != 0) break;
        const acl_permset_mask_t writes = ACL_WRITE_DATA | ACL_APPEND_DATA | ACL_DELETE |
            ACL_DELETE_CHILD | ACL_WRITE_ATTRIBUTES | ACL_WRITE_EXTATTRIBUTES |
            ACL_WRITE_SECURITY | ACL_CHANGE_OWNER;
        // Conservative: no principal/membership/deny-order inference, even for inherited
        // or inherit-only grants. These can grant mutation beyond st_mode on Darwin.
        if (permissions & writes) { result = 1; break; }
    }
done:
    acl_free(acl);
    return result;
}
#elif defined(__linux__)
#include <sys/xattr.h>

int av_check_acl(int descriptor, int ancestor) {
    (void)ancestor;
    // Linux POSIX ACL effective named permissions are masked by the group mode bits.
    // Still require ACL-free paths: include directory defaults to prevent inheritance.
    // NFSv4/rich ACL and unsupported xattr custody are not certified by this check.
    const char *names[] = {"system.posix_acl_access", "system.posix_acl_default"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (fgetxattr(descriptor, names[i], 0, 0) >= 0) return 1;
        if (errno != ENODATA) return -1;
    }
    return 0;
}
#else
int av_check_acl(int descriptor, int ancestor) {
    (void)descriptor; (void)ancestor;
    return -1;
}
#endif
