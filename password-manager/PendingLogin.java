public class PendingLogin {
    private final String token;
    private final String email;
    private final String vaultKey;
    private final Double latitude;
    private final Double longitude;
    private final String code;
    private final LoginRiskResult riskResult;

    public PendingLogin(
        String token,
        String email,
        String vaultKey,
        Double latitude,
        Double longitude,
        String code,
        LoginRiskResult riskResult
    ) {
        this.token = token;
        this.email = email;
        this.vaultKey = vaultKey;
        this.latitude = latitude;
        this.longitude = longitude;
        this.code = code;
        this.riskResult = riskResult;
    }

    public String getToken() {
        return token;
    }

    public String getEmail() {
        return email;
    }

    public String getVaultKey() {
        return vaultKey;
    }

    public Double getLatitude() {
        return latitude;
    }

    public Double getLongitude() {
        return longitude;
    }

    public String getCode() {
        return code;
    }

    public LoginRiskResult getRiskResult() {
        return riskResult;
    }
}
