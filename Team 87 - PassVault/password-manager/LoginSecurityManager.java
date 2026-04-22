import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Stack;
import java.util.UUID;

public class LoginSecurityManager {
    private static final double IMPOSSIBLE_TRAVEL_LIMIT_KMPH = 1100.0;
    private static final int FAILED_ATTEMPTS_PER_SUSPENSION = 5;
    private static final int BASE_SUSPENSION_MINUTES = 10;
    private static final SecureRandom RANDOM = new SecureRandom();

    public static class SuspensionStatus {
        private final boolean suspended;
        private final Instant suspendedUntilUtc;

        public SuspensionStatus(boolean suspended, Instant suspendedUntilUtc) {
            this.suspended = suspended;
            this.suspendedUntilUtc = suspendedUntilUtc;
        }

        public boolean isSuspended() {
            return suspended;
        }

        public Instant getSuspendedUntilUtc() {
            return suspendedUntilUtc;
        }
    }

    public static SuspensionStatus getSuspensionStatus(String email) throws Exception {
        ensureSecurityRow(email);

        String sql = "SELECT suspended_until_utc FROM login_security WHERE user_email = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);

            try (ResultSet rs = stmt.executeQuery()) {
                if (!rs.next()) {
                    return new SuspensionStatus(false, null);
                }

                Timestamp suspendedUntil = rs.getTimestamp("suspended_until_utc");
                if (suspendedUntil == null) {
                    return new SuspensionStatus(false, null);
                }

                Instant until = suspendedUntil.toInstant();
                return new SuspensionStatus(until.isAfter(Instant.now()), until);
            }
        }
    }

    public static void recordFailedLogin(String email) throws Exception {
        ensureSecurityRow(email);

        String selectSql = "SELECT failed_attempts, suspension_level FROM login_security WHERE user_email = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement select = conn.prepareStatement(selectSql)) {
            select.setString(1, email);

            int failedAttempts = 0;
            int suspensionLevel = 0;
            try (ResultSet rs = select.executeQuery()) {
                if (rs.next()) {
                    failedAttempts = rs.getInt("failed_attempts");
                    suspensionLevel = rs.getInt("suspension_level");
                }
            }

            failedAttempts++;
            Instant suspendedUntil = null;
            int nextSuspensionLevel = suspensionLevel;

            if (failedAttempts % FAILED_ATTEMPTS_PER_SUSPENSION == 0) {
                int minutes = BASE_SUSPENSION_MINUTES * (int) Math.pow(2, suspensionLevel);
                suspendedUntil = Instant.now().plus(Duration.ofMinutes(minutes));
                nextSuspensionLevel = suspensionLevel + 1;
            }

            String updateSql =
                "UPDATE login_security SET failed_attempts = ?, suspension_level = ?, " +
                "suspended_until_utc = COALESCE(?, suspended_until_utc) WHERE user_email = ?";
            try (PreparedStatement update = conn.prepareStatement(updateSql)) {
                update.setInt(1, failedAttempts);
                update.setInt(2, nextSuspensionLevel);
                update.setTimestamp(3, suspendedUntil == null ? null : Timestamp.from(suspendedUntil));
                update.setString(4, email);
                update.executeUpdate();
            }
        }
    }

    public static void resetFailedAttempts(String email) throws Exception {
        ensureSecurityRow(email);

        String sql =
            "UPDATE login_security SET failed_attempts = 0, suspended_until_utc = NULL " +
            "WHERE user_email = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);
            stmt.executeUpdate();
        }
    }

    public static LoginRiskResult analyzeLogin(String email, Double latitude, Double longitude) throws Exception {
        Stack<LoginRecord> historyStack = getLoginHistoryStack(email);
        Instant currentTimeUtc = Instant.now();

        Map<String, Object> currentLogin = new HashMap<>();
        currentLogin.put("latitude", latitude);
        currentLogin.put("longitude", longitude);
        currentLogin.put("timeUtc", currentTimeUtc);

        if (historyStack.isEmpty()) {
            return new LoginRiskResult(false, "FIRST_LOGIN", null);
        }

        LoginRecord previousLogin = historyStack.peek();
        Double currentLatitude = (Double) currentLogin.get("latitude");
        Double currentLongitude = (Double) currentLogin.get("longitude");
        Instant currentInstant = (Instant) currentLogin.get("timeUtc");

        if (!previousLogin.hasLocation() || currentLatitude == null || currentLongitude == null) {
            return new LoginRiskResult(false, "LOCATION_UNAVAILABLE", null);
        }

        double distanceKm = haversineKm(
            previousLogin.getLatitude(),
            previousLogin.getLongitude(),
            currentLatitude,
            currentLongitude
        );
        long seconds = Math.max(
            Duration.between(previousLogin.getLoginTimeUtc(), currentInstant).getSeconds(),
            1
        );
        double speedKmph = distanceKm / (seconds / 3600.0);

        if (speedKmph > IMPOSSIBLE_TRAVEL_LIMIT_KMPH) {
            return new LoginRiskResult(true, "HIGH_RISK_IMPOSSIBLE_TRAVEL", speedKmph);
        }

        return new LoginRiskResult(false, "NORMAL", speedKmph);
    }

    public static void recordSuccessfulLogin(
        String email,
        Double latitude,
        Double longitude,
        LoginRiskResult riskResult
    ) throws Exception {
        resetFailedAttempts(email);

        String sql =
            "INSERT INTO login_history " +
            "(user_email, latitude, longitude, login_time_utc, speed_kmph, risk_status) " +
            "VALUES (?, ?, ?, UTC_TIMESTAMP(), ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);
            setNullableDouble(stmt, 2, latitude);
            setNullableDouble(stmt, 3, longitude);
            setNullableDouble(stmt, 4, riskResult.getSpeedKmph());
            stmt.setString(5, riskResult.getRiskStatus());
            stmt.executeUpdate();
        }

        clearTwoFactor(email);
    }

    public static PendingLogin createPendingLogin(
        String email,
        String vaultKey,
        Double latitude,
        Double longitude,
        LoginRiskResult riskResult
    ) throws Exception {
        String token = UUID.randomUUID().toString();
        String code = String.format("%06d", RANDOM.nextInt(1_000_000));
        PendingLogin pendingLogin = new PendingLogin(token, email, vaultKey, latitude, longitude, code, riskResult);
        PendingLoginStore.put(pendingLogin);

        String sql =
            "UPDATE login_security SET two_factor_required = TRUE, two_factor_code = ? " +
            "WHERE user_email = ?";
        ensureSecurityRow(email);
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, code);
            stmt.setString(2, email);
            stmt.executeUpdate();
        }

        return pendingLogin;
    }

    public static PendingLogin completePendingLogin(String token, String code) throws Exception {
        PendingLogin pendingLogin = PendingLoginStore.get(token);
        if (pendingLogin == null || code == null || !pendingLogin.getCode().equals(code.trim())) {
            return null;
        }

        PendingLoginStore.remove(token);
        recordSuccessfulLogin(
            pendingLogin.getEmail(),
            pendingLogin.getLatitude(),
            pendingLogin.getLongitude(),
            pendingLogin.getRiskResult()
        );
        return pendingLogin;
    }

    private static Stack<LoginRecord> getLoginHistoryStack(String email) throws Exception {
        Stack<LoginRecord> stack = new Stack<>();

        String sql =
            "SELECT user_email, latitude, longitude, login_time_utc FROM login_history " +
            "WHERE user_email = ? ORDER BY login_time_utc ASC, id ASC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    stack.push(new LoginRecord(
                        rs.getString("user_email"),
                        getNullableDouble(rs, "latitude"),
                        getNullableDouble(rs, "longitude"),
                        rs.getTimestamp("login_time_utc").toInstant()
                    ));
                }
            }
        }

        return stack;
    }

    private static void ensureSecurityRow(String email) throws Exception {
        if (email == null || email.isBlank()) {
            return;
        }

        String sql =
            "INSERT INTO login_security (user_email) " +
            "SELECT ? FROM users WHERE email = ? " +
            "ON DUPLICATE KEY UPDATE user_email = user_email";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);
            stmt.setString(2, email);
            stmt.executeUpdate();
        }
    }

    private static void clearTwoFactor(String email) throws Exception {
        String sql =
            "UPDATE login_security SET two_factor_required = FALSE, two_factor_code = NULL " +
            "WHERE user_email = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);
            stmt.executeUpdate();
        }
    }

    private static double haversineKm(double lat1, double lon1, double lat2, double lon2) {
        final double earthRadiusKm = 6371.0;
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a =
            Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(Math.toRadians(lat1)) *
            Math.cos(Math.toRadians(lat2)) *
            Math.sin(dLon / 2) *
            Math.sin(dLon / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return earthRadiusKm * c;
    }

    private static void setNullableDouble(PreparedStatement stmt, int index, Double value) throws Exception {
        if (value == null) {
            stmt.setNull(index, java.sql.Types.DOUBLE);
            return;
        }

        stmt.setDouble(index, value);
    }

    private static Double getNullableDouble(ResultSet rs, String column) throws Exception {
        double value = rs.getDouble(column);
        return rs.wasNull() ? null : value;
    }
}
