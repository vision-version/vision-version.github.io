import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegularClaName {
    public static List<String> findMatches(String input) {
        List<String> matches = new ArrayList<>();
        Pattern pattern = Pattern.compile("(?:^|\\s)[A-Z]+[a-z0-9_]+([A-Z][a-z0-9_]*)+(?=\\s|$)");
        Matcher matcher = pattern.matcher(input);
        while (matcher.find()) {
            matches.add(matcher.group());
        }
        if (matches.isEmpty()) {
            return matches;
        }        
        for (int i = 0; i < matches.size(); i++) {
            String str = matches.get(i);
            String trimmedStr = str.trim();
            matches.set(i, trimmedStr);
        }
        return matches;
    }
    public static void main(String[] args){
        List<String> re = findMatches(" via JwtRequestCodeFilter ");
        System.out.println(re);
    }
}