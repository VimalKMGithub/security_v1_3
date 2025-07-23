package org.vimal.security.v1.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "dummy")
@Getter
@Setter
public class DummyUsersConfig {
    private String godUserUsername;
    private String globalAdminUserUsername;
    private String superAdminUserUsername;
    private String adminUserUsername;
    private String godUserEmail;
    private String globalAdminUserEmail;
    private String superAdminUserEmail;
    private String adminUserEmail;
    private String godUserPassword;
    private String globalAdminUserPassword;
    private String superAdminUserPassword;
    private String adminUserPassword;
}