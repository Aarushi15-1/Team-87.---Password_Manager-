public class LoginRiskResult {
    private final boolean highRisk;
    private final String riskStatus;
    private final Double speedKmph;

    public LoginRiskResult(boolean highRisk, String riskStatus, Double speedKmph) {
        this.highRisk = highRisk;
        this.riskStatus = riskStatus;
        this.speedKmph = speedKmph;
    }

    public boolean isHighRisk() {
        return highRisk;
    }

    public String getRiskStatus() {
        return riskStatus;
    }

    public Double getSpeedKmph() {
        return speedKmph;
    }
}
