import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegularPathName {
    public static List<String> findMatches(String input) {
        if(input.substring(input.length()-1).equals(".")){
            input = input.substring(0,input.length() - 1);
        }
        if(input.substring(input.length()-1).equals(",")){
            input = input.substring(0,input.length() - 1);
        }
        List<String> matches = new ArrayList<>();
        Pattern pattern1 = Pattern.compile("(?:^|\\s)[\\w-_]*/[\\w-_]+(?:/[\\w-_]+)*/[\\w]*\\.*[\\w]*(?=\\s|$)");
        Pattern pattern2 = Pattern.compile("(?:^|\\s)[A-Za-z-_]+\\.[\\w-_]+(?:\\.[\\w-_]+)*\\.*[\\w]*(?=\\s|$)");
        Matcher matcher1 = pattern1.matcher(input);
        Matcher matcher2 = pattern2.matcher(input);
        while (matcher1.find()) {
            matches.add(matcher1.group());
        }
        while (matcher2.find()) {
            matches.add(matcher2.group());
        }
        if (matches.isEmpty()) {
            return matches;
        }
        for (int i = 0; i < matches.size(); i++) {
            String str = matches.get(i);
            String trimmedStr = str.trim();
            matches.set(i, trimmedStr);
        }
        List<String> result = new ArrayList<>(matches);
        for (int i = 0; i < result.size(); i++) {
            for (int j = i + 1; j < result.size(); j++) {
                String s1 = result.get(i);
                String s2 = result.get(j);
                if (s1.contains(s2)) {
                    result.remove(j);
                    j--;
                } else if (s2.contains(s1)) {
                    result.remove(i);
                    i--;
                    break;
                }
            }
        }
        return result;
    }
    public static void main(String[] args){
        List<String> re = findMatches("activemq-broker/src/main/java/org/apache/activemq/filter/XalanXPathEvaluator.java diff | blob | history activemq-client/src/main/java/org/apache/activemq/filter/XPathExpression.java activemq.git/commit projects / activemq.git / commit commit grep author committer pickaxe ? search: re summary | shortlog | log | commit | commitdiff | tree (parent: 4fa1035 ) | patch https://issues.apache.org/jira/browse/AMQ-5333 - make xpath parser features configurable author Dejan Bosanac <dejan@nighttale.net> Tue, 26 Aug 2014 12:46:45 +0000 (14:46 +0200) committer Dejan Bosanac <dejan@nighttale.net> Tue, 26 Aug 2014 12:47:06 +0000 (14:47 +0200) commit b9696ac80bb496b52d05c3884f81b0746d9af9e2 tree 1365553d949715862759824d11b1668675c80ce5 tree | snapshot parent 4fa10356f09908d8cfb9fd4448983ac6d7e80ee7 commit | diff https://issues.apache.org/jira/browse/AMQ-5333 - make xpath parser features configurable activemq-broker/src/main/java/org/apache/activemq/filter/JAXPXPathEvaluator.java diff | blob | history activemq-broker/src/main/java/org/apache/activemq/filter/XalanXPathEvaluator.java diff | blob | history activemq-client/src/main/java/org/apache/activemq/filter/XPathExpression.java diff | blob | history Apache ActiveMQ RSS Atom");
        System.out.println(re);
    }
}