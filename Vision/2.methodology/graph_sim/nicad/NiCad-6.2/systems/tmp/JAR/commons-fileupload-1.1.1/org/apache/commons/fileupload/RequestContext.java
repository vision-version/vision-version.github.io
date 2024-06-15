package org.apache.commons.fileupload;

import java.io.IOException;
import java.io.InputStream;

public interface RequestContext {
  String getCharacterEncoding();
  
  String getContentType();
  
  int getContentLength();
  
  InputStream getInputStream() throws IOException;
}
