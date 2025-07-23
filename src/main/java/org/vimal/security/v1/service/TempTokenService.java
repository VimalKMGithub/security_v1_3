package org.vimal.security.v1.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.vimal.security.v1.repo.TempTokenRepo;

import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TempTokenService {
    private final TempTokenRepo tempTokenRepo;

    public void storeToken(String key,
                           String token,
                           Duration ttl) {
        tempTokenRepo.saveToken(key, token, ttl);
    }

    public Optional<String> retrieveToken(String key) {
        var token = tempTokenRepo.getToken(key);
        return Optional.ofNullable(token);
    }

    public List<String> retrieveTokens(Collection<String> keys) {
        return tempTokenRepo.getTokens(keys);
    }

    public void removeToken(String key) {
        tempTokenRepo.deleteToken(key);
    }

    public void removeTokens(Collection<String> keys) {
        tempTokenRepo.deleteTokens(keys);
    }

    public void removeEverything() {
        tempTokenRepo.deleTeEverything();
    }
}