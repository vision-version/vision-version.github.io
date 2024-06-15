package org.apache.commons.fileupload.servlet;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUpload;
import org.apache.commons.fileupload.FileUploadException;

public class ServletFileUpload extends FileUpload {
  public ServletFileUpload() {}
  
  public ServletFileUpload(FileItemFactory fileItemFactory) {
    super(fileItemFactory);
  }
  
  public List parseRequest(HttpServletRequest request) throws FileUploadException {
    return parseRequest(new ServletRequestContext(request));
  }
}
