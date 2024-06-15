package org.apache.commons.fileupload.portlet;

import java.io.IOException;
import java.io.InputStream;
import javax.portlet.ActionRequest;
import org.apache.commons.fileupload.RequestContext;

public class PortletRequestContext implements RequestContext {
  private ActionRequest request;
  
  public PortletRequestContext(ActionRequest request) {
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
    return this.request.getPortletInputStream();
  }
  
  public String toString() {
    return "ContentLength=" + getContentLength() + ", ContentType=" + getContentType();
  }
}
