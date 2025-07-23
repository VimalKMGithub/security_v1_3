package org.vimal.security.v1.util.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.JoseException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.vimal.security.v1.config.properties.JwtConfig;
import org.vimal.security.v1.converter.JwtId2EncrypterDecrypter;
import org.vimal.security.v1.converter.JwtIdEncrypterDecrypter;
import org.vimal.security.v1.converter.RefreshToken2EncrypterDecrypter;
import org.vimal.security.v1.converter.RefreshTokenEncrypterDecrypter;
import org.vimal.security.v1.exception.BadRequestExc;
import org.vimal.security.v1.impl.UserDetailsImpl;
import org.vimal.security.v1.model.UserModel;
import org.vimal.security.v1.repo.UserModelRepo;
import org.vimal.security.v1.service.TempTokenService;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Component
public class JwtUtil {
    private static final long ACCESS_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(30);
    private static final long REFRESH_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(60 * 24 * 7);
    private static final String JWT_ID_PREFIX = "jwtId:";
    private static final String REFRESH_TOKEN_PREFIX = "refreshToken:";
    private static final String REFRESH_TOKEN_MAPPING_PREFIX = "refresh_token_mapping:";
    private final SecretKey signingKey;
    private final AesKey encryptionKey;
    private final UserModelRepo userModelRepo;
    private final TempTokenService tempTokenService;
    private final JwtIdEncrypterDecrypter jwtIdEncrypterDecrypter;
    private final JwtId2EncrypterDecrypter jwtId2EncrypterDecrypter;
    private final RefreshTokenEncrypterDecrypter refreshTokenEncrypterDecrypter;
    private final RefreshToken2EncrypterDecrypter refreshToken2EncrypterDecrypter;

    public JwtUtil(JwtConfig jwtConfig,
                   UserModelRepo userModelRepo,
                   TempTokenService tempTokenService,
                   JwtIdEncrypterDecrypter jwtIdEncrypterDecrypter,
                   JwtId2EncrypterDecrypter jwtId2EncrypterDecrypter,
                   RefreshTokenEncrypterDecrypter refreshTokenEncrypterDecrypter,
                   RefreshToken2EncrypterDecrypter refreshToken2EncrypterDecrypter) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtConfig.getSigningSecret()));
        this.encryptionKey = new AesKey(Decoders.BASE64.decode(jwtConfig.getEncryptionSecret()));
        this.userModelRepo = userModelRepo;
        this.tempTokenService = tempTokenService;
        this.jwtIdEncrypterDecrypter = jwtIdEncrypterDecrypter;
        this.jwtId2EncrypterDecrypter = jwtId2EncrypterDecrypter;
        this.refreshTokenEncrypterDecrypter = refreshTokenEncrypterDecrypter;
        this.refreshToken2EncrypterDecrypter = refreshToken2EncrypterDecrypter;
    }

    private String generateAndStoreJwtId(UserModel user) {
        var jwtId = UUID.randomUUID().toString();
        var redisKey = JWT_ID_PREFIX + user.getId();
        var encryptedKey = jwtIdEncrypterDecrypter.convertToDatabaseColumn(redisKey);
        var encryptedJwtId = jwtId2EncrypterDecrypter.convertToDatabaseColumn(jwtId);
        tempTokenService.storeToken(encryptedKey, encryptedJwtId, Duration.ofSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS));
        return jwtId;
    }

    private Map<String, Object> buildTokenClaims(UserModel user) {
        var authorities = new HashSet<>();
        user.getRoles().forEach(role -> {
            authorities.add(role.getRoleName());
            role.getPermissions().forEach(permission ->
                    authorities.add(permission.getPermissionName()));
        });
        return Map.of(
                "jwt_id", generateAndStoreJwtId(user),
                "user_id", user.getId().toString(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "authorities", authorities,
                "mfa_enabled", user.isMfaEnabled(),
                "mfa_methods", user.getEnabledMfaMethods().stream()
                        .map(UserModel.MfaType::name)
                        .collect(Collectors.toSet()),
                "issued_at", Instant.now().toString(),
                "expiration", Instant.now().plusSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS).toString()
        );
    }

    private String createSignedToken(Map<String, Object> claims) {
        return Jwts.builder()
                .claims(claims)
                .signWith(signingKey)
                .compact();
    }

    private String encryptToken(String jws) throws JoseException {
        var jwe = new JsonWebEncryption();
        jwe.setPayload(jws);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jwe.setKey(encryptionKey);
        jwe.setAlgorithmConstraints(new AlgorithmConstraints(
                        AlgorithmConstraints.ConstraintType.PERMIT,
                        KeyManagementAlgorithmIdentifiers.A256KW
                )
        );
        jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(
                        AlgorithmConstraints.ConstraintType.PERMIT,
                        ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512
                )
        );
        return jwe.getCompactSerialization();
    }

    private String generateAndStoreRefreshToken(UserModel user) {
        var userKey = REFRESH_TOKEN_PREFIX + user.getId();
        var encryptedUserKey = refreshTokenEncrypterDecrypter.convertToDatabaseColumn(userKey);
        var existingToken = tempTokenService.retrieveToken(encryptedUserKey);
        if (existingToken.isPresent())
            return refreshToken2EncrypterDecrypter.convertToEntityAttribute(existingToken.get());
        var newRefreshToken = UUID.randomUUID().toString();
        var reverseLookupKey = REFRESH_TOKEN_MAPPING_PREFIX + newRefreshToken;
        var encryptedReverseLookupKey = refreshTokenEncrypterDecrypter.convertToDatabaseColumn(reverseLookupKey);
        try {
            var encryptedRefreshToken = refreshToken2EncrypterDecrypter.convertToDatabaseColumn(newRefreshToken);
            tempTokenService.storeToken(encryptedUserKey,
                    encryptedRefreshToken,
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_IN_SECONDS
                    )
            );
            var encryptedUserId = refreshToken2EncrypterDecrypter.convertToDatabaseColumn(user.getId().toString());
            tempTokenService.storeToken(encryptedReverseLookupKey,
                    encryptedUserId,
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_IN_SECONDS
                    )
            );
            return newRefreshToken;
        } catch (Exception e) {
            tempTokenService.removeToken(encryptedUserKey);
            tempTokenService.removeToken(encryptedReverseLookupKey);
            throw new RuntimeException("Failed to generate refresh token: " + e.getMessage(), e);
        }
    }

    private Map<String, Object> generateAccessToken(UserModel user) throws JoseException {
        var claims = buildTokenClaims(user);
        var jws = createSignedToken(claims);
        return Map.of(
                "access_token", encryptToken(jws),
                "expires_in_seconds", ACCESS_TOKEN_EXPIRES_IN_SECONDS,
                "token_type", "Bearer"
        );
    }

    public Map<String, Object> generateTokens(UserModel user) throws JoseException {
        var tokens = new java.util.HashMap<>(generateAccessToken(user));
        var refreshToken = generateAndStoreRefreshToken(user);
        tokens.put("refresh_token", refreshToken);
        user.recordSuccessfulMfaAttempt();
        user.setLastLoginAt(Instant.now());
        userModelRepo.save(user);
        return tokens;
    }

    private String decryptToken(String token) throws JoseException {
        var jwe = new JsonWebEncryption();
        jwe.setKey(encryptionKey);
        jwe.setCompactSerialization(token);
        return jwe.getPayload();
    }

    private Claims parseToken(String jws) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(jws)
                .getPayload();
    }

    @SuppressWarnings("unchecked")
    public UserDetailsImpl verifyAccessToken(String token) throws JoseException {
        var jws = decryptToken(token);
        var claims = parseToken(jws);
        if (Instant.parse(claims.get("issued_at", String.class)).isAfter(Instant.now()))
            throw new BadRequestExc("Token is not yet valid");
        if (Instant.parse(claims.get("expiration", String.class)).isBefore(Instant.now()))
            throw new BadRequestExc("Token has expired");
        var userIdStr = claims.get("user_id", String.class);
        var jwtId = claims.get("jwt_id", String.class);
        var redisKey = JWT_ID_PREFIX + userIdStr;
        var encryptedKey = jwtIdEncrypterDecrypter.convertToDatabaseColumn(redisKey);
        var storedJwtId = tempTokenService.retrieveToken(encryptedKey);
        if (storedJwtId.isEmpty()) throw new BadRequestExc("Invalid token: token ID not found");
        var decryptedJwtId = jwtId2EncrypterDecrypter.convertToEntityAttribute(storedJwtId.get());
        if (!decryptedJwtId.equals(jwtId)) throw new BadRequestExc("Token ID does not match");
        var username = claims.get("username", String.class);
        var email = claims.get("email", String.class);
        var userId = UUID.fromString(userIdStr);
        List<String> authoritiesList = claims.get("authorities", List.class);
        var authorities = authoritiesList.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        var mfaEnabled = claims.get("mfa_enabled", Boolean.class);
        List<String> mfaMethodNames = claims.get("mfa_methods", List.class);
        Set<UserModel.MfaType> mfaMethods = mfaMethodNames.stream()
                .map(UserModel.MfaType::valueOf)
                .collect(Collectors.toSet());
        var tokenUser = new UserModel();
        tokenUser.setId(userId);
        tokenUser.setUsername(username);
        tokenUser.setEmail(email);
        tokenUser.setMfaEnabled(mfaEnabled);
        tokenUser.setEnabledMfaMethods(mfaMethods);
        return new UserDetailsImpl(tokenUser, authorities);
    }

    private String getEncryptedReverseLookupKey(String refreshToken) {
        var reverseLookupKey = REFRESH_TOKEN_MAPPING_PREFIX + refreshToken;
        return refreshTokenEncrypterDecrypter.convertToDatabaseColumn(reverseLookupKey);
    }

    private String getIdByEncryptedReverseLookupKey(String encryptedReverseLookupKey) {
        var encryptedUserId = tempTokenService.retrieveToken(encryptedReverseLookupKey).orElseThrow(() -> new BadRequestExc("Invalid or expired refresh token"));
        return refreshToken2EncrypterDecrypter.convertToEntityAttribute(encryptedUserId);
    }

    private UserModel verifyRefreshToken(String refreshToken) {
        var encryptedReverseLookupKey = getEncryptedReverseLookupKey(refreshToken);
        var userId = getIdByEncryptedReverseLookupKey(encryptedReverseLookupKey);
        var userKey = REFRESH_TOKEN_PREFIX + userId;
        var encryptedKey = refreshTokenEncrypterDecrypter.convertToDatabaseColumn(userKey);
        var storedRefreshToken = tempTokenService.retrieveToken(encryptedKey).orElseThrow(() -> new BadRequestExc("Invalid or expired refresh token"));
        var decryptedStoredRefreshToken = refreshToken2EncrypterDecrypter.convertToEntityAttribute(storedRefreshToken);
        if (!decryptedStoredRefreshToken.equals(refreshToken)) throw new BadRequestExc("Invalid refresh token");
        return userModelRepo.findById(UUID.fromString(userId)).orElseThrow(() -> new BadRequestExc("User not found"));
    }

    public Map<String, Object> refreshAccessToken(String refreshToken) throws JoseException {
        var user = verifyRefreshToken(refreshToken);
        return generateAccessToken(user);
    }

    private String getEncryptedJwtId(UserModel user) {
        var jwtKey = JWT_ID_PREFIX + user.getId();
        return jwtIdEncrypterDecrypter.convertToDatabaseColumn(jwtKey);
    }

    public void revokeAccessToken(UserModel userModel) {
        var encryptedKey = getEncryptedJwtId(userModel);
        tempTokenService.removeToken(encryptedKey);
    }

    public void revokeRefreshToken(String refreshToken) {
        var encryptedReverseLookupKey = getEncryptedReverseLookupKey(refreshToken);
        var userId = getIdByEncryptedReverseLookupKey(encryptedReverseLookupKey);
        tempTokenService.removeToken(encryptedReverseLookupKey);
        var userKey = REFRESH_TOKEN_PREFIX + userId;
        var encryptedKey = refreshTokenEncrypterDecrypter.convertToDatabaseColumn(userKey);
        tempTokenService.removeToken(encryptedKey);
    }

    private String getEncryptedRefreshTokenId(UserModel userModel) {
        var userKey = REFRESH_TOKEN_PREFIX + userModel.getId();
        return refreshTokenEncrypterDecrypter.convertToDatabaseColumn(userKey);
    }

    private String getEncryptedRefreshTokenMappingId(String encryptedRefreshToken) {
        var refreshToken = refreshToken2EncrypterDecrypter.convertToEntityAttribute(encryptedRefreshToken);
        var reverseLookupKey = REFRESH_TOKEN_MAPPING_PREFIX + refreshToken;
        return refreshTokenEncrypterDecrypter.convertToDatabaseColumn(reverseLookupKey);
    }

    public void revokeRefreshTokenByUser(UserModel userModel) {
        var encryptedKey = getEncryptedRefreshTokenId(userModel);
        var encryptedRefreshToken = tempTokenService.retrieveToken(encryptedKey);
        if (encryptedRefreshToken.isPresent()) {
            var encryptedReverseLookupKey = getEncryptedRefreshTokenMappingId(encryptedRefreshToken.get());
            tempTokenService.removeToken(encryptedReverseLookupKey);
        }
        tempTokenService.removeToken(encryptedKey);
    }

    public void revokeAccessTokens(Collection<UserModel> users) {
        var encryptedKeys = users.stream()
                .map(this::getEncryptedJwtId)
                .collect(Collectors.toSet());
        tempTokenService.removeTokens(encryptedKeys);
    }

    public void revokeRefreshTokensByUsers(Collection<UserModel> users) {
        var encryptedKeys = users.stream()
                .map(this::getEncryptedRefreshTokenId)
                .collect(Collectors.toSet());
        var encryptedRefreshTokens = tempTokenService.retrieveTokens(encryptedKeys);
        var encryptedReverseLookupKeys = encryptedRefreshTokens.stream().filter(Objects::nonNull)
                .map(this::getEncryptedRefreshTokenMappingId)
                .collect(Collectors.toSet());
        encryptedKeys.addAll(encryptedReverseLookupKeys);
        tempTokenService.removeTokens(encryptedKeys);
    }
}