import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PhishingService {

    public static PhishingAnalysisResult analyzeAndStore(String email, String url) throws Exception {
        PhishingDetectorEngine detector = new PhishingDetectorEngine();
        PhishingAnalysisResult result = detector.analyze(url);
        saveScan(email, result);
        return result;
    }

    public static List<PhishingScan> getRecentScans(String email, int limit) throws Exception {
        List<PhishingScan> scans = new ArrayList<>();
        String sql =
            "SELECT url, score, verdict, detail, DATE_FORMAT(scanned_at, '%Y-%m-%d %H:%i:%s') AS scanned_at_display " +
            "FROM phishing_scans WHERE user_email = ? ORDER BY scanned_at DESC, id DESC LIMIT ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);
            ps.setInt(2, limit);

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    scans.add(new PhishingScan(
                        rs.getString("url"),
                        rs.getInt("score"),
                        rs.getString("verdict"),
                        rs.getString("detail"),
                        rs.getString("scanned_at_display")
                    ));
                }
            }
        }

        return scans;
    }

    public static Map<String, Integer> getStats(String email) throws Exception {
        Map<String, Integer> stats = new HashMap<>();
        stats.put("total", 0);
        stats.put("highRisk", 0);

        String sql =
            "SELECT COUNT(*) AS total, " +
            "SUM(CASE WHEN score >= 6 THEN 1 ELSE 0 END) AS high_risk " +
            "FROM phishing_scans WHERE user_email = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    stats.put("total", rs.getInt("total"));
                    stats.put("highRisk", rs.getInt("high_risk"));
                }
            }
        }

        return stats;
    }

    private static void saveScan(String email, PhishingAnalysisResult result) throws Exception {
        String sql =
            "INSERT INTO phishing_scans (user_email, url, score, verdict, detail, reasons) VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, email);
            ps.setString(2, result.getUrl());
            ps.setInt(3, result.getScore());
            ps.setString(4, result.getVerdict());
            ps.setString(5, result.getDetail());
            ps.setString(6, String.join("\n", result.getReasons()));
            ps.executeUpdate();
        }
    }
}
