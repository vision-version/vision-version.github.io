package org.apache.commons.fileupload.portlet;

import java.util.List;
import javax.portlet.ActionRequest;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUpload;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;

public class PortletFileUpload extends FileUpload {
  public static final boolean isMultipartContent(ActionRequest request) {
    return FileUploadBase.isMultipartContent(new PortletRequestContext(request));
  }
  
  public PortletFileUpload() {}
  
  public PortletFileUpload(FileItemFactory fileItemFactory) {
    super(fileItemFactory);
  }
  
  public List parseRequest(ActionRequest request) throws FileUploadException {
    return parseRequest(new PortletRequestContext(request));
  }
}
