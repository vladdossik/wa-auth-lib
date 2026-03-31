package org.wa.auth.lib.service;

import java.util.UUID;

public interface AdminService {
    boolean isUserBlocked(UUID externalId);
}
