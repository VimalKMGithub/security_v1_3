package org.vimal.security.v1.repo;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

@Repository
@RequiredArgsConstructor
public class TempTokenRepo {
    private final RedisTemplate<String, String> redisTemplate;

    public void saveToken(String key,
                          String token,
                          Duration ttl) {
        redisTemplate.opsForValue().set(key, token, ttl);
    }

    public String getToken(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public List<String> getTokens(Collection<String> keys) {
        return redisTemplate.opsForValue().multiGet(keys);
    }

    public void deleteToken(String key) {
        redisTemplate.delete(key);
    }

    public void deleteTokens(Collection<String> keys) {
        redisTemplate.delete(keys);
    }

    public void deleTeEverything() {
        Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection().serverCommands().flushAll();
    }
}