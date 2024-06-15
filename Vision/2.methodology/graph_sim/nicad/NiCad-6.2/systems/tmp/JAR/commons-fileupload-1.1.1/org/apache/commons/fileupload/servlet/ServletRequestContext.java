package org.apache.commons.fileupload.servlet;

import java.io.IOException;
import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.fileupload.RequestContext;

public class ServletRequestContext implements RequestContext {
  private HttpServletRequest request;
  
  public ServletRequestContext(HttpServletRequest request) {
    this.request = request;
  }
  
  public String getCharacterEncoding() {
    return this.request.getCharacterEncoding();
  }
  
  public String getContentType() {
    return this.request.getContentType();
  }
  
  public int getContentLength() {
    return this.request.getContentLength();
  }
  
  public InputStream getInputStream() throws IOException {
    return (InputStream)this.request.getInputStream();
  }
  
  public String toString() {
    return "ContentLength=" + getContentLength() + ", ContentType=" + getContentType();
  }
}
