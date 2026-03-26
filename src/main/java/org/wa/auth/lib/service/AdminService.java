package org.wa.auth.lib.service;

import java.util.UUID;

public interface AdminService {
    boolean isBlocked(UUID externalId);
}
