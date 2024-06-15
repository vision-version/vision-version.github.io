import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegularMethodName {
    public static List<String> findMatches(String input) {
        List<String> matches = new ArrayList<>();
        Pattern pattern = Pattern.compile("\\b(\\w+\\.)*[a-z]+[A-Z][0-9_a-z]+\\b");
        Matcher matcher = pattern.matcher(input);
        while (matcher.find()) {
            matches.add(matcher.group());
        }
        return matches;
    }
    public static void main(String[] args){
        List<String> re = findMatches("createDestination.action The org.h2.util.JdbcUtils.getConnection method of the H2 database takes as parameters the class name of the driver and URL of the database. An attacker may pass a JNDI driver name and a URL leading to a LDAP or RMI servers, causing remote code execution. This can be exploited through various attack vectors, most notably through the H2 Console which leads to unauthenticated remote code execution.");
        System.out.println(re);
    }
}