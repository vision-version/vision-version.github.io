package org.apache.commons.fileupload;

import java.util.HashMap;
import java.util.Map;

public class ParameterParser {
  private char[] chars = null;
  
  private int pos = 0;
  
  private int len = 0;
  
  private int i1 = 0;
  
  private int i2 = 0;
  
  private boolean lowerCaseNames = false;
  
  private boolean hasChar() {
    return (this.pos < this.len);
  }
  
  private String getToken(boolean quoted) {
    while (this.i1 < this.i2 && Character.isWhitespace(this.chars[this.i1]))
      this.i1++; 
    while (this.i2 > this.i1 && Character.isWhitespace(this.chars[this.i2 - 1]))
      this.i2--; 
    if (quoted && 
      this.i2 - this.i1 >= 2 && this.chars[this.i1] == '"' && this.chars[this.i2 - 1] == '"') {
      this.i1++;
      this.i2--;
    } 
    String result = null;
    if (this.i2 > this.i1)
      result = new String(this.chars, this.i1, this.i2 - this.i1); 
    return result;
  }
  
  private boolean isOneOf(char ch, char[] charray) {
    boolean result = false;
    for (int i = 0; i < charray.length; i++) {
      if (ch == charray[i]) {
        result = true;
        break;
      } 
    } 
    return result;
  }
  
  private String parseToken(char[] terminators) {
    this.i1 = this.pos;
    this.i2 = this.pos;
    while (hasChar()) {
      char ch = this.chars[this.pos];
      if (isOneOf(ch, terminators))
        break; 
      this.i2++;
      this.pos++;
    } 
    return getToken(false);
  }
  
  private String parseQuotedToken(char[] terminators) {
    this.i1 = this.pos;
    this.i2 = this.pos;
    boolean quoted = false;
    boolean charEscaped = false;
    while (hasChar()) {
      char ch = this.chars[this.pos];
      if (!quoted && isOneOf(ch, terminators))
        break; 
      if (!charEscaped && ch == '"')
        quoted = !quoted; 
      charEscaped = (!charEscaped && ch == '\\');
      this.i2++;
      this.pos++;
    } 
    return getToken(true);
  }
  
  public boolean isLowerCaseNames() {
    return this.lowerCaseNames;
  }
  
  public void setLowerCaseNames(boolean b) {
    this.lowerCaseNames = b;
  }
  
  public Map parse(String str, char separator) {
    if (str == null)
      return new HashMap(); 
    return parse(str.toCharArray(), separator);
  }
  
  public Map parse(char[] chars, char separator) {
    if (chars == null)
      return new HashMap(); 
    return parse(chars, 0, chars.length, separator);
  }
  
  public Map parse(char[] chars, int offset, int length, char separator) {
    if (chars == null)
      return new HashMap(); 
    HashMap params = new HashMap();
    this.chars = chars;
    this.pos = offset;
    this.len = length;
    String paramName = null;
    String paramValue = null;
    while (hasChar()) {
      paramName = parseToken(new char[] { '=', separator });
      paramValue = null;
      if (hasChar() && chars[this.pos] == '=') {
        this.pos++;
        paramValue = parseQuotedToken(new char[] { separator });
      } 
      if (hasChar() && chars[this.pos] == separator)
        this.pos++; 
      if (paramName != null && paramName.length() > 0) {
        if (this.lowerCaseNames)
          paramName = paramName.toLowerCase(); 
        params.put(paramName, paramValue);
      } 
    } 
    return params;
  }
}
