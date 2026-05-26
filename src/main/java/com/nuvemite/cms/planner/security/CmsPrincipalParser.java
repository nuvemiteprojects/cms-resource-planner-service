package com.nuvemite.cms.planner.security;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.security.oauth2.jwt.Jwt;

public final class CmsPrincipalParser {

    private CmsPrincipalParser() {}

    public static CmsUserPrincipal fromJwt(Jwt jwt) {
        return CmsUserPrincipal.fromClaims(
                jwt.getSubject(),
                resolvePlatformRole(jwt),
                jwt.getClaimAsStringList("company_ids"),
                jwt.getClaimAsStringList("premise_ids"),
                jwt.getClaim("company_memberships"));
    }

    private static String resolvePlatformRole(Jwt jwt) {
        Set<String> realmRoles = realmRoles(jwt);
        if (realmRoles.contains("REGULATOR")) {
            return "REGULATOR";
        }
        if (realmRoles.contains("ADMIN")) {
            return "ADMIN";
        }
        if (realmRoles.contains("COMPANY_USER")) {
            return "COMPANY_USER";
        }
        return jwt.getClaimAsString("platform_role");
    }

    private static Set<String> realmRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        Object roles = realmAccess != null ? realmAccess.get("roles") : null;
        if (roles instanceof List<?> roleList) {
            return roleList.stream().map(String::valueOf).collect(Collectors.toSet());
        }
        return Set.of();
    }

    static Set<UUID> parseUuids(List<String> values) {
        if (values == null || values.isEmpty()) {
            return new HashSet<>();
        }
        return values.stream().map(UUID::fromString).collect(Collectors.toCollection(HashSet::new));
    }
}
