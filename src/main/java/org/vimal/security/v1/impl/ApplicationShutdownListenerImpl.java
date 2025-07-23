package org.vimal.security.v1.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.stereotype.Component;
import org.vimal.security.v1.service.TempTokenService;

@Slf4j
@Component
@RequiredArgsConstructor
public class ApplicationShutdownListenerImpl implements ApplicationListener<ContextClosedEvent> {
    private final TempTokenService tempTokenService;

    @Override
    public void onApplicationEvent(ContextClosedEvent event) {
        log.info("Application is shutting down. Removing all temporary tokens from redis...");
        tempTokenService.removeEverything();
        log.info("All temporary tokens removed successfully.");
    }
}