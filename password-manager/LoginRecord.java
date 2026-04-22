import java.time.Instant;

public class LoginRecord {
    private final String email;
    private final Double latitude;
    private final Double longitude;
    private final Instant loginTimeUtc;

    public LoginRecord(String email, Double latitude, Double longitude, Instant loginTimeUtc) {
        this.email = email;
        this.latitude = latitude;
        this.longitude = longitude;
        this.loginTimeUtc = loginTimeUtc;
    }

    public String getEmail() {
        return email;
    }

    public Double getLatitude() {
        return latitude;
    }

    public Double getLongitude() {
        return longitude;
    }

    public Instant getLoginTimeUtc() {
        return loginTimeUtc;
    }

    public boolean hasLocation() {
        return latitude != null && longitude != null;
    }
}
