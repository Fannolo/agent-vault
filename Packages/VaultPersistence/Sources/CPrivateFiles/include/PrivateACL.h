#ifndef AV_PRIVATE_ACL_H
#define AV_PRIVATE_ACL_H

// Descriptor-only check. 0 = verified, 1 = disallowed ACL, -1 = unsupported/unreadable.
// Private boundaries require no ACL; ancestors reject Darwin allow-write entries.
int av_check_acl(int descriptor, int ancestor);

#endif
