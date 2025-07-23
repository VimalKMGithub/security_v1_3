package org.vimal.security.v1.util.otp;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

public final class TOTPUtil {
    private static final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

    private TOTPUtil() {
        throw new AssertionError("Cannot instantiate TOTPUtil class");
    }

    public static String generateBase32Secret() throws NoSuchAlgorithmException {
        var keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());
        keyGenerator.init(160);
        var secretKey = keyGenerator.generateKey();
        return new Base32().encodeToString(secretKey.getEncoded()).replace("=", "");
    }

    public static String generateTOTPUrl(String issuer, String accountName, String base32Secret) {
        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                urlEncode(issuer),
                urlEncode(accountName),
                base32Secret,
                urlEncode(issuer)
        );
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String generateCurrentOTP(String base64Secret) throws InvalidKeyException {
        var secretKey = decodeBase32Secret(base64Secret);
        var code = totp.generateOneTimePassword(secretKey, Instant.now());
        return String.format("%06d", code);
    }

    public static boolean verifyOTP(String base32Secret,
                                    String userInputCode) throws InvalidKeyException {
        return generateCurrentOTP(base32Secret).equals(userInputCode);
    }

    private static SecretKey decodeBase32Secret(String base32Secret) {
        var keyBytes = new Base32().decode(base32Secret);
        return new SecretKeySpec(keyBytes, totp.getAlgorithm());
    }
}