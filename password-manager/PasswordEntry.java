public class PasswordEntry {

    private String website;
    private String username;
    private String encryptedPassword;
    private String strength;

    public PasswordEntry(String website, String username, String encryptedPassword, String strength) {
        this.website = website;
        this.username = username;
        this.encryptedPassword = encryptedPassword;
        this.strength = strength;
    }

    public String getWebsite() {
        return website;
    }

    public String getUsername() {
        return username;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public String getStrength() {
        return strength;
    }

    // Convert object → file format
    public String toFileString() {
        return website + "," + username + "," + encryptedPassword + "," + strength;
    }

    // Convert file → object
    public static PasswordEntry fromFileString(String line) {
        String[] parts = line.split(",");
        return new PasswordEntry(parts[0], parts[1], parts[2], parts[3]);
    }
}